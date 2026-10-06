"""Tests for scripts/validate_rules.py.

Fixtures live in tests/fixtures/validate/:

* valid/                  one passing rule per contract key, laid out like sigma/
* invalid/<ID>_<case>/    one mini sigma/ tree per case; must fail with exactly <ID>
* network/V017_*/         cases that need MITRE ATT&CK data (downloaded by pySigma)

The invalid cases run with sigma check (V017) turned off so they are offline and
deterministic. Tests that need V017 are skipped when the ATT&CK/D3FEND data can be neither
downloaded nor read from pySigma's cache (~/.cache/pysigma).
"""

from __future__ import annotations

import functools
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_rules  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "validate"
CONTRACT_PATH = REPO_ROOT / "config" / "logsource_contract.yml"
SCRIPT = REPO_ROOT / "scripts" / "validate_rules.py"
INVALID_CASES = sorted(p for p in (FIXTURES / "invalid").iterdir() if p.is_dir())
ALL_OFFLINE_IDS = [f"V{n:03d}" for n in range(1, 17)]


@functools.cache
def mitre_data_available() -> bool:
    """True when pySigma can load ATT&CK and D3FEND data (network or warm cache)."""
    try:
        from sigma.data import mitre_attack, mitre_d3fend

        return bool(mitre_attack.mitre_attack_techniques) and mitre_d3fend.mitre_d3fend_version is not None
    except Exception:  # noqa: BLE001 - any download/cache failure means "no data"
        return False


needs_network = pytest.mark.skipif(
    "not mitre_data_available()",
    reason="needs MITRE ATT&CK/D3FEND data (network access or pySigma cache) for sigma check (V017)",
)


@pytest.fixture(scope="module")
def contract() -> validate_rules.Contract:
    return validate_rules.load_contract(CONTRACT_PATH)


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def failure_ids(results) -> set[str]:
    return {f.check_id for r in results for f in r.failures}


# --- valid fixtures --------------------------------------------------------------------------


def test_one_valid_fixture_per_contract_key(contract):
    stems = [p.stem for p in (FIXTURES / "valid").rglob("*.yml")]
    for key in contract.entries:
        assert sum(1 for s in stems if s.startswith(f"{key}_")) == 1, key
    assert len(stems) == len(contract.entries) == 15


def test_valid_fixtures_pass_offline_checks(contract):
    results = validate_rules.validate(FIXTURES / "valid", contract, sigma_check=False)
    assert len(results) == 15
    assert [(r.display, r.failures) for r in results if r.failures] == []


@needs_network
def test_valid_fixtures_pass_all_checks_including_sigma_check():
    proc = run_cli("--rules", "tests/fixtures/validate/valid", "--contract", "config/logsource_contract.yml")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout == ""


# --- invalid fixtures ------------------------------------------------------------------------


def test_every_offline_check_has_an_invalid_fixture():
    covered = {case.name[:4] for case in INVALID_CASES}
    assert covered == set(ALL_OFFLINE_IDS)


@pytest.mark.parametrize("case", INVALID_CASES, ids=[c.name for c in INVALID_CASES])
def test_invalid_fixture_fails_with_exactly_its_check(case, contract):
    expected = case.name[:4]
    results = validate_rules.validate(case, contract, sigma_check=False)
    assert results, "case folder has no files"
    assert failure_ids(results) == {expected}, [
        f"{r.display}: {f.check_id}: {f.message}" for r in results for f in r.failures
    ]


@needs_network
def test_v017_unknown_technique_fails_sigma_check():
    case = "tests/fixtures/validate/network/V017_unknown_technique"
    proc = run_cli("--rules", case, "--contract", "config/logsource_contract.yml")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    lines = proc.stdout.strip().splitlines()
    assert lines, proc.stderr
    assert all(": V017: " in line for line in lines), lines
    assert "attack.t9999" in proc.stdout


# --- the real rule library -------------------------------------------------------------------


def test_real_sigma_folder_passes(contract):
    if mitre_data_available():
        proc = run_cli("--rules", "sigma", "--contract", "config/logsource_contract.yml")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Checked 10 rule files" in proc.stderr
    else:
        # Offline: everything except V017 must still pass.
        results = validate_rules.validate(REPO_ROOT / "sigma", contract, sigma_check=False)
        assert [(r.display, r.failures) for r in results if r.failures] == []


def test_rule_template_passes_every_check(contract, tmp_path):
    rules = tmp_path / "sigma"
    (rules / "aws").mkdir(parents=True)
    template = REPO_ROOT / "templates" / "rule_template.yml"
    (rules / "aws" / "aws_cloudtrail_iam_user_created.yml").write_text(
        template.read_text(encoding="utf-8"), encoding="utf-8"
    )
    results = validate_rules.validate(rules, contract, sigma_check=mitre_data_available())
    assert [(r.display, r.failures) for r in results if r.failures] == []


def test_sigma_check_that_cannot_run_is_reported_as_v017(contract, tmp_path, monkeypatch):
    broken = tmp_path / "sigma_validation.yml"
    broken.write_text("validators:\n  - no_such_validator\n", encoding="utf-8")
    monkeypatch.setattr(validate_rules, "SIGMA_VALIDATION_CONFIG", broken)
    results = validate_rules.validate(REPO_ROOT / "sigma", contract)
    assert results and all(
        [f.check_id for f in r.failures] == ["V017"] and "failed to run" in r.failures[0].message
        for r in results
    )


# --- command-line behaviour ------------------------------------------------------------------


def test_cli_prints_one_line_per_failure_and_exits_1():
    proc = run_cli(
        "--rules", "tests/fixtures/validate/invalid/V004_level_low",
        "--contract", "config/logsource_contract.yml",
    )
    # V004 fixture is offline-safe for V017 too: sigma check does not look at level.
    assert proc.returncode == 1
    lines = [line for line in proc.stdout.splitlines() if ": V0" in line]
    assert any(
        line.startswith("tests/fixtures/validate/invalid/V004_level_low/aws/aws_cloudtrail_level_low.yml: V004: ")
        for line in lines
    ), proc.stdout


def test_cli_missing_rules_folder_is_usage_error():
    proc = run_cli("--rules", "does-not-exist", "--contract", "config/logsource_contract.yml")
    assert proc.returncode == 2


def test_cli_bad_contract_is_usage_error(tmp_path):
    bad = tmp_path / "contract.yml"
    bad.write_text("version: 1\n", encoding="utf-8")
    proc = run_cli("--rules", "sigma", "--contract", str(bad))
    assert proc.returncode == 2


def test_cli_missing_argument_is_usage_error():
    proc = run_cli("--rules", "sigma")
    assert proc.returncode == 2


def test_junit_has_one_case_per_file_and_one_failure_per_check(contract, tmp_path):
    case = FIXTURES / "invalid" / "V003_duplicate_id"
    results = validate_rules.validate(case, contract, sigma_check=False)
    out = tmp_path / "validation.xml"
    validate_rules.write_junit(results, out)
    cases = list(ET.parse(out).getroot().iter("testcase"))
    assert len(cases) == 2
    for tc in cases:
        failures = tc.findall("failure")
        assert len(failures) == 1
        assert failures[0].get("type") == "V003"
