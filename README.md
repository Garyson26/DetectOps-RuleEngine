# DetectOps-RuleEngine

Detection as Code for Oakbrook's security monitoring. Detection rules are written once in
[Sigma](https://sigmahq.io/), reviewed like software, checked automatically, and translated
into the query languages of each SIEM we run: Microsoft Sentinel (KQL), Microsoft Defender XDR
(KQL) and Splunk (SPL).

## Workflow

1. **Pull request.** Every rule change goes through a pull request and review.
2. **Pre-commit.** Before each commit, hooks on your machine check YAML, whitespace, private
   keys and secrets (gitleaks), and run the rule validator.
3. **CI.** The pipeline lints the rules (the same validator), translates them to KQL and SPL,
   checks that the committed translations in `platform-translations/` are up to date, and runs
   the tests.
4. **Deploy.** Deployment to each SIEM will be added later.

## Repository layout

```
sigma/<folder>/              Sigma rules, one per .yml file. Folders: windows, linux, aws, azure, gcp
config/
  logsource_contract.yml     Shared contract: allowed log sources, fields, levels, status, targets
  sigma_validation.yml       Validator settings for `sigma check` (check V017)
templates/rule_template.yml  Commented example rule to copy
scripts/validate_rules.py    Rule validator (checks V001 to V017)
tests/                       pytest tests and fixtures; sample-logs/ is reserved for a later stage
platform-translations/       Generated KQL/SPL, committed, drift-checked in CI (do not edit by hand)
pipelines/                   pySigma field mappings per SIEM
reports/                     Generated reports (git-ignored)
```

## Set up locally

You need Python 3.12 and Git.

```bash
python3.12 -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements-validate.txt
pre-commit install                # run the hooks on every commit
```

## Validate rules

```bash
python scripts/validate_rules.py --rules sigma --contract config/logsource_contract.yml
```

Add `--junit reports/validation.xml` to write a JUnit report. Exit codes: `0` all rules
passed, `1` one or more rules failed, `2` usage or configuration error. Each failure is printed
as `<path>: <CHECK_ID>: <message>`. Check IDs are listed in [CONTRIBUTING.md](CONTRIBUTING.md).

Check V017 runs `sigma check`, which downloads MITRE ATT&CK and D3FEND data the first time it
runs (cached in `~/.cache/pysigma`), so it needs internet access.

## Run the tests and hooks

```bash
pytest -q tests/test_validate_rules.py
pre-commit run --all-files
```

Tests that need the ATT&CK data are skipped when it cannot be downloaded or found in the cache.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before writing a rule. It covers the rule standard,
how to choose a log source, severity levels and how to change the contract.
