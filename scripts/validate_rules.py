#!/usr/bin/env python3
"""Validate Sigma rules against the DetectOps rule standard and log source contract.

Usage:
    python scripts/validate_rules.py --rules sigma --contract config/logsource_contract.yml \
        [--junit reports/validation.xml]

Exit codes: 0 all rules passed, 1 one or more rules failed, 2 usage or config error.

Prints one line per failure: ``<path>: <CHECK_ID>: <message>``.

Check IDs V001 to V017 are documented in CONTRIBUTING.md. Two checks wrap external tools
and only report on a file when every earlier check passed for it, so each problem is
reported once, under its most specific ID:

* V016 (pySigma parse) reports only for files that passed V001 to V015.
* V017 (``sigma check``) reports only for files that passed V001 to V016.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sigma.exceptions import SigmaError
from sigma.modifiers import SigmaAllModifier, SigmaContainsModifier
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaFieldReference

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_VALIDATION_CONFIG = REPO_ROOT / "config" / "sigma_validation.yml"

REQUIRED_KEYS = (
    "title", "id", "status", "description", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
)
OPTIONAL_KEYS = ("references", "modified", "related")

# Files that may sit in a rules folder without being rules.
IGNORED_FILES = {".gitkeep"}

FILENAME_RE = re.compile(r"^[a-z0-9_]+\.yml$")
FILENAME_MAX_LEN = 90
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Enterprise ATT&CK tactics in pySigma tag format (tactic short name, lowercase, hyphenated).
# pySigma 1.5.1 does not bundle ATT&CK data (sigma.data.mitre_attack downloads it at runtime),
# so the list is hard-coded here. Source: MITRE ATT&CK Enterprise v19.2, x-mitre-tactic
# objects' x_mitre_shortname in
# https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack.json
# ATT&CK v19 replaced Defense Evasion (TA0005) with Stealth (TA0005) and Defense Impairment
# (TA0112), so there are 15 tactics. The hyphenated form is what pySigma's ATT&CK tag
# validator (V017) accepts; underscore forms such as attack.initial_access fail it.
ATTACK_TACTICS = frozenset({
    "reconnaissance",          # TA0043
    "resource-development",    # TA0042
    "initial-access",          # TA0001
    "execution",               # TA0002
    "persistence",             # TA0003
    "privilege-escalation",    # TA0004
    "stealth",                 # TA0005
    "defense-impairment",      # TA0112
    "credential-access",       # TA0006
    "discovery",               # TA0007
    "lateral-movement",        # TA0008
    "collection",              # TA0009
    "command-and-control",     # TA0011
    "exfiltration",            # TA0010
    "impact",                  # TA0040
})
TECHNIQUE_TAG_RE = re.compile(r"^t\d{4}(\.\d{3})?$")
# Other ATT&CK object tags pySigma accepts: groups, software, mitigations, data sources.
ATTACK_OTHER_TAG_RE = re.compile(r"^(g|s|m)\d{4}$|^ds\d{4}$")
# Generic tag shape for non-ATT&CK namespaces (car, cve, d3fend, detection, stp, tlp).
# Namespace and per-namespace patterns are enforced by sigma check (V017).
GENERIC_TAG_RE = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")

CONTAINS_ONLY_ALLOWED = (SigmaContainsModifier, SigmaAllModifier)


class ContractError(Exception):
    """The contract file is missing or malformed."""


class _StringDateLoader(yaml.SafeLoader):
    """SafeLoader that keeps YAML timestamps as strings, so V006 can check them itself."""


_StringDateLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


@dataclass
class ContractEntry:
    key: str
    folder: str
    logsource: dict[str, str]
    fields: frozenset[str]
    contains_only_fields: frozenset[str]


@dataclass
class Contract:
    allowed_levels: tuple[str, ...]
    allowed_status: tuple[str, ...]
    entries: dict[str, ContractEntry]

    @property
    def folders(self) -> set[str]:
        return {entry.folder for entry in self.entries.values()}

    def match_logsource(self, logsource: Any) -> ContractEntry | None:
        if not isinstance(logsource, dict):
            return None
        for entry in self.entries.values():
            if logsource == entry.logsource:
                return entry
        return None


@dataclass
class Failure:
    check_id: str
    message: str


@dataclass
class RuleResult:
    path: Path
    display: str
    failures: list[Failure] = field(default_factory=list)
    doc: dict[str, Any] | None = None
    text: str | None = None
    entry: ContractEntry | None = None

    def fail(self, check_id: str, message: str) -> None:
        self.failures.append(Failure(check_id, message))


def load_contract(path: Path) -> Contract:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractError(f"cannot read contract: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"contract is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("contract must be a mapping")
    try:
        entries = {}
        for key, raw in data["logsources"].items():
            entries[key] = ContractEntry(
                key=key,
                folder=str(raw["folder"]),
                logsource={str(k): str(v) for k, v in raw["logsource"].items()},
                fields=frozenset(raw["fields"]),
                contains_only_fields=frozenset(raw.get("contains_only_fields", [])),
            )
        return Contract(
            allowed_levels=tuple(data["allowed_levels"]),
            allowed_status=tuple(data["allowed_status"]),
            entries=entries,
        )
    except (KeyError, TypeError, AttributeError) as exc:
        raise ContractError(f"contract is missing or has a malformed key: {exc}") from exc


def display_path(rules_arg: str, rel: Path) -> str:
    return (Path(rules_arg) / rel).as_posix()


def discover(rules_dir: Path, rules_arg: str, contract: Contract) -> tuple[list[RuleResult], list[RuleResult]]:
    """Return (rule files to check, non-rule files that are failures in their own right)."""
    rules: list[RuleResult] = []
    strays: list[RuleResult] = []
    for path in sorted(p for p in rules_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(rules_dir)
        result = RuleResult(path=path, display=display_path(rules_arg, rel))
        if path.name in IGNORED_FILES:
            continue
        if path.suffix != ".yml":
            result.fail("V009", f"only .yml rule files are allowed under the rules folder, found '{path.name}'")
            strays.append(result)
            continue
        if len(rel.parts) != 2 or rel.parts[0] not in contract.folders:
            result.fail(
                "V008",
                f"rule files must sit directly in one of: {', '.join(sorted(contract.folders))}",
            )
            strays.append(result)
            continue
        rules.append(result)
    return rules, strays


# --- per-rule checks -------------------------------------------------------------------------


def check_v001(r: RuleResult) -> bool:
    try:
        r.text = r.path.read_text(encoding="utf-8")
        docs = list(yaml.load_all(r.text, Loader=_StringDateLoader))
    except (OSError, UnicodeDecodeError) as exc:
        r.fail("V001", f"cannot read file: {exc}")
        return False
    except yaml.YAMLError as exc:
        r.fail("V001", f"invalid YAML: {' '.join(str(exc).split())}")
        return False
    if len(docs) != 1:
        r.fail("V001", f"expected exactly one YAML document, found {len(docs)}")
        return False
    if not isinstance(docs[0], dict):
        r.fail("V001", "rule must be a YAML mapping")
        return False
    r.doc = docs[0]
    return True


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def check_v002(r: RuleResult) -> None:
    doc = r.doc
    missing = [k for k in REQUIRED_KEYS if k not in doc or (k != "falsepositives" and _is_empty(doc[k]))]
    if missing:
        r.fail("V002", f"missing or empty required keys: {', '.join(missing)}")
    unknown = sorted(str(k) for k in doc if k not in REQUIRED_KEYS and k not in OPTIONAL_KEYS)
    if unknown:
        r.fail("V002", f"keys not allowed by the rule standard: {', '.join(unknown)}")


def check_v003_format(r: RuleResult) -> None:
    value = r.doc.get("id")
    if value is None:
        return
    if not isinstance(value, str) or not UUID4_RE.match(value):
        r.fail("V003", f"id '{value}' is not a lowercase UUID version 4")


def check_v004(r: RuleResult, contract: Contract) -> None:
    value = r.doc.get("level")
    if value is not None and value not in contract.allowed_levels:
        r.fail("V004", f"level '{value}' not in allowed levels: {', '.join(contract.allowed_levels)}")


def check_v005(r: RuleResult, contract: Contract) -> None:
    value = r.doc.get("status")
    if value is not None and value not in contract.allowed_status:
        r.fail("V005", f"status '{value}' not in allowed status: {', '.join(contract.allowed_status)}")


def check_v006(r: RuleResult) -> None:
    for key in ("date", "modified"):
        value = r.doc.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not DATE_RE.match(value):
            r.fail("V006", f"{key} '{value}' must use YYYY-MM-DD")
            continue
        try:
            dt.date.fromisoformat(value)
        except ValueError:
            r.fail("V006", f"{key} '{value}' is not a real calendar date")


def check_v007(r: RuleResult, contract: Contract) -> None:
    logsource = r.doc.get("logsource")
    if logsource is None:
        return
    r.entry = contract.match_logsource(logsource)
    if r.entry is None:
        r.fail("V007", f"logsource {logsource} does not exactly match any contract entry")


def check_v008(r: RuleResult) -> None:
    if r.entry is None:
        return
    folder = r.path.parent.name
    if folder != r.entry.folder:
        r.fail("V008", f"contract entry '{r.entry.key}' rules belong in '{r.entry.folder}/', not '{folder}/'")


def check_v009(r: RuleResult) -> None:
    name = r.path.name
    if not FILENAME_RE.match(name):
        r.fail("V009", f"file name '{name}' must use only lowercase a-z, 0-9 and _ with a .yml extension")
        return
    if len(name) > FILENAME_MAX_LEN:
        r.fail("V009", f"file name is {len(name)} characters, maximum is {FILENAME_MAX_LEN}")
        return
    if r.entry is not None:
        prefix = f"{r.entry.key}_"
        if not name.startswith(prefix) or len(name) <= len(prefix) + len(".yml"):
            r.fail("V009", f"file name must be '{prefix}<what_it_detects>.yml'")


def check_v010(r: RuleResult) -> None:
    tags = r.doc.get("tags")
    if tags is None:
        return
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        r.fail("V010", "tags must be a list of strings")
        return
    has_tactic = has_technique = False
    for tag in tags:
        if tag != tag.lower():
            r.fail("V010", f"tag '{tag}' must be lowercase")
            continue
        namespace, _, name = tag.partition(".")
        if namespace == "attack":
            if name in ATTACK_TACTICS:
                has_tactic = True
            elif TECHNIQUE_TAG_RE.match(name):
                has_technique = True
            elif ATTACK_OTHER_TAG_RE.match(name):
                pass
            elif name.replace("_", "-") in ATTACK_TACTICS:
                r.fail("V010", f"tag '{tag}' must use the hyphenated tactic name 'attack.{name.replace('_', '-')}'")
            else:
                r.fail("V010", f"tag '{tag}' is not a known ATT&CK tactic or a technique tag (attack.tNNNN[.NNN])")
        elif not GENERIC_TAG_RE.match(tag):
            r.fail("V010", f"tag '{tag}' is not in '<namespace>.<name>' format")
    if not has_tactic:
        r.fail("V010", "at least one ATT&CK tactic tag is required (e.g. attack.execution)")
    if not has_technique:
        r.fail("V010", "at least one ATT&CK technique tag is required (e.g. attack.t1059.001)")


def check_v014(r: RuleResult) -> None:
    if "falsepositives" not in r.doc:
        return  # reported by V002
    value = r.doc["falsepositives"]
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v.strip() for v in value):
        r.fail("V014", "falsepositives must be a non-empty list of descriptions")


def _detection_items(detection: SigmaDetection):
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            yield from _detection_items(item)
        else:
            yield item


def check_v016_parse(r: RuleResult) -> SigmaRule | None:
    """Parse with pySigma. Returns the rule, or None with the error recorded as V016."""
    try:
        rule = SigmaRule.from_yaml(r.text)
        for condition in rule.detection.parsed_condition:
            condition.parse()
        return rule
    except SigmaError as exc:
        r.fail("V016", f"pySigma cannot parse the rule: {exc}")
    except Exception as exc:  # noqa: BLE001 - pySigma can raise plain exceptions on bad input
        r.fail("V016", f"pySigma cannot parse the rule: {type(exc).__name__}: {exc}")
    return None


def check_v011_to_v013(r: RuleResult, rule: SigmaRule) -> None:
    entry = r.entry
    for name, detection in rule.detection.detections.items():
        for item in _detection_items(detection):
            item: SigmaDetectionItem
            if item.field is None:
                r.fail("V013", f"detection '{name}' uses keyword (unbound) values; bind every value to a field")
                continue
            if entry is None:
                continue
            referenced = [item.field] + [v.field for v in item.value if isinstance(v, SigmaFieldReference)]
            for fieldname in referenced:
                if fieldname not in entry.fields:
                    r.fail("V011", f"field '{fieldname}' in detection '{name}' is not listed for contract entry '{entry.key}'")
            if item.field in entry.contains_only_fields:
                modifiers = item.modifiers
                ok = (
                    any(m is SigmaContainsModifier for m in modifiers)
                    and all(m in CONTAINS_ONLY_ALLOWED for m in modifiers)
                )
                if not ok:
                    used = "|".join(m.__name__.removeprefix("Sigma").removesuffix("Modifier").lower() for m in modifiers) or "none"
                    r.fail("V012", f"field '{item.field}' may only use the contains modifier (optionally with all), found: {used}")


def check_rule(r: RuleResult, contract: Contract) -> None:
    if not check_v001(r):
        return
    check_v002(r)
    check_v003_format(r)
    check_v004(r, contract)
    check_v005(r, contract)
    check_v006(r)
    check_v007(r, contract)
    check_v008(r)
    check_v009(r)
    check_v010(r)
    check_v014(r)


# --- cross-rule checks -----------------------------------------------------------------------


def check_uniqueness(results: list[RuleResult]) -> None:
    ids: dict[str, list[RuleResult]] = defaultdict(list)
    titles: dict[str, list[RuleResult]] = defaultdict(list)
    for r in results:
        if r.doc is None:
            continue
        if isinstance(r.doc.get("id"), str):
            ids[r.doc["id"].lower()].append(r)
        if isinstance(r.doc.get("title"), str) and r.doc["title"].strip():
            titles[" ".join(r.doc["title"].lower().split())].append(r)
    for value, group in ids.items():
        if len(group) > 1:
            for r in group:
                others = ", ".join(o.display for o in group if o is not r)
                r.fail("V003", f"id '{value}' is also used by {others}")
    for _, group in titles.items():
        if len(group) > 1:
            for r in group:
                others = ", ".join(o.display for o in group if o is not r)
                r.fail("V015", f"title '{r.doc['title']}' is also used by {others}")


def run_sigma_check(rules_dir: Path) -> tuple[dict[Path, list[str]], str | None]:
    """Run ``sigma check`` over the rules folder.

    Returns (issues per resolved rule path, global error or None). sigma-cli is invoked as a
    module of the current interpreter so it always uses the same environment as this script.
    """
    with tempfile.TemporaryDirectory() as tmp:
        junit = Path(tmp) / "sigma_check.xml"
        cmd = [
            sys.executable, "-m", "sigma.cli.main", "check",
            "--fail-on-issues",
            "-c", str(SIGMA_VALIDATION_CONFIG),
            "--junitxml", str(junit),
            str(rules_dir),
        ]
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
        per_file: dict[Path, list[str]] = defaultdict(list)
        # The XML is written by sigma-cli into our own temp folder during this run, so it is trusted.
        if junit.exists():
            for case in ET.parse(junit).getroot().iter("testcase"):
                failure = case.find("failure")
                if failure is None:
                    continue
                file_attr = case.get("file", "")
                detail = (failure.text or "").strip()
                message = f"{failure.get('message', 'sigma check issue')}"
                if detail:
                    message += f" ({detail})"
                tag = _extract_tag_detail(proc.stdout, file_attr, failure.get("message", ""))
                if tag:
                    message += f" [{tag}]"
                try:
                    per_file[Path(file_attr).resolve()].append(message)
                except (OSError, ValueError):
                    per_file[Path(file_attr)].append(message)
        if proc.returncode != 0 and not per_file:
            tail = " | ".join(line.strip() for line in (proc.stdout + proc.stderr).strip().splitlines()[-5:])
            return {}, f"sigma check failed to run (exit {proc.returncode}): {tail}"
        return per_file, None


_ISSUE_LINE_RE = re.compile(r"^issue=(?P<issue>\S+) .* rule=(?P<rules>.+?) (?P<extra>\w+=.*)$")


def _extract_tag_detail(stdout: str, file_attr: str, junit_message: str) -> str | None:
    """Pull extra fields (e.g. tag=attack.t9999) from sigma check's console output for one issue."""
    issue_name = junit_message.split(":", 1)[0].strip()
    details = []
    for line in stdout.splitlines():
        m = _ISSUE_LINE_RE.match(line.strip())
        if m and m.group("issue") == issue_name and file_attr in m.group("rules"):
            details.append(m.group("extra").strip())
    return "; ".join(dict.fromkeys(details)) or None


# --- orchestration ---------------------------------------------------------------------------


def validate(rules_dir: Path, contract: Contract, rules_arg: str | None = None, sigma_check: bool = True) -> list[RuleResult]:
    """Validate every file under rules_dir. Returns one RuleResult per file checked."""
    rules_arg = rules_arg if rules_arg is not None else str(rules_dir)
    rules, strays = discover(rules_dir, rules_arg, contract)
    for r in rules:
        check_rule(r, contract)
    check_uniqueness(rules)

    for r in rules:
        if r.doc is None:
            continue
        before = len(r.failures)
        rule = check_v016_parse(r)
        if rule is None:
            # V016 reports only when no earlier check explains the failure.
            if before:
                del r.failures[before:]
            continue
        check_v011_to_v013(r, rule)

    if sigma_check:
        per_file, global_error = run_sigma_check(rules_dir)
        if global_error:
            for r in rules:
                if not r.failures:
                    r.fail("V017", global_error)
        else:
            for r in rules:
                if r.failures:
                    continue  # V017 reports only for files that passed V001 to V016
                for message in per_file.get(r.path.resolve(), []):
                    r.fail("V017", f"sigma check: {message}")

    return sorted(rules + strays, key=lambda r: r.display)


def write_junit(results: list[RuleResult], path: Path) -> None:
    failures = sum(1 for r in results if r.failures)
    suite = ET.Element(
        "testsuite",
        name="validate_rules",
        tests=str(len(results)),
        failures=str(failures),
        errors="0",
    )
    for r in results:
        case = ET.SubElement(suite, "testcase", classname="validate_rules", name=r.display, file=r.display)
        for f in r.failures:
            failure = ET.SubElement(case, "failure", message=f"{f.check_id}: {f.message}", type=f.check_id)
            failure.text = f"{r.display}: {f.check_id}: {f.message}"
    root = ET.Element("testsuites")
    root.append(suite)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules", required=True, help="Root folder of the Sigma rules (e.g. sigma)")
    parser.add_argument("--contract", required=True, help="Path to config/logsource_contract.yml")
    parser.add_argument("--junit", help="Write a JUnit XML report to this path")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_OK if exc.code == 0 else EXIT_USAGE

    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        print(f"error: rules folder not found: {args.rules}", file=sys.stderr)
        return EXIT_USAGE
    if not SIGMA_VALIDATION_CONFIG.is_file():
        print(f"error: sigma check config not found: {SIGMA_VALIDATION_CONFIG}", file=sys.stderr)
        return EXIT_USAGE
    try:
        contract = load_contract(Path(args.contract))
    except ContractError as exc:
        print(f"error: {args.contract}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    results = validate(rules_dir, contract, rules_arg=args.rules)
    for r in results:
        for f in r.failures:
            print(f"{r.display}: {f.check_id}: {f.message}")
    if args.junit:
        write_junit(results, Path(args.junit))

    failed = sum(1 for r in results if r.failures)
    sys.stdout.flush()
    print(f"Checked {len(results)} rule files: {len(results) - failed} passed, {failed} failed.", file=sys.stderr)
    return EXIT_FAILED if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
