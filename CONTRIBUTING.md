# Contributing detection rules

This guide is for anyone adding or changing a rule in `sigma/`. Start from
[`templates/rule_template.yml`](templates/rule_template.yml), which passes every check and
explains each key.

## Steps

1. Create a branch.
2. Pick the contract key for your log source (see below).
3. Copy the template to `sigma/<folder>/<contract key>_<what_it_detects>.yml` and fill it in.
4. Run the validator and fix every failure:
   `python scripts/validate_rules.py --rules sigma --contract config/logsource_contract.yml`
5. Commit (the pre-commit hooks run the validator again) and open a pull request.

## Choosing the contract key

[`config/logsource_contract.yml`](config/logsource_contract.yml) lists every log source we
support. Each entry has a key (for example `win_process_creation`), a `folder`, the exact
`logsource` block to use, and the `fields` you may use in `detection`.

- Find the entry whose `logsource` describes the events you need, for example
  `{product: aws, service: cloudtrail}` for CloudTrail API calls.
- Copy its `logsource` block into your rule exactly. Do not add or change keys.
- Put the rule in that entry's `folder`, and start the file name with the entry's key.
- Use only the fields listed in that entry's `fields`.
- Check `targets` to see where the rule will run. For example, `win_network_connection` has no
  `sentinel` target, so those rules convert for Defender XDR and Splunk only. Fields named in a
  target's `unsupported_fields` cannot be translated for that target.

If no entry fits, do not write the rule against a made-up log source. Ask for a contract change
(see below).

## Rule standard

- One rule per file, extension `.yml`, stored in `sigma/<folder>/` where `<folder>` is the
  contract entry's `folder`.
- File name: `<contract key>_<what_it_detects>.yml`. Lowercase `a-z`, `0-9` and `_` only,
  90 characters maximum. Example: `aws_cloudtrail_trail_logging_stopped.yml`.
- Required keys: `title`, `id`, `status`, `description`, `author`, `date`, `tags`, `logsource`,
  `detection`, `falsepositives`, `level`.
- Optional keys: `references`, `modified`, `related`. No other keys.
- `id`: UUID version 4, unique across the repo. `title` unique across the repo.
- `status`: `experimental` for all new rules.
- `date` and `modified`: `YYYY-MM-DD`.
- `level`: `critical`, `high` or `medium` only.
- `logsource`: exactly the keys and values of one contract entry, nothing extra.
- `tags`: at least one ATT&CK tactic tag (`attack.<tactic>`) and at least one technique tag
  (`attack.tNNNN` or `attack.tNNNN.NNN`). Lowercase. Write tactics in pySigma's format: the
  hyphenated ATT&CK short name, for example `attack.initial-access`, `attack.defense-impairment`
  or `attack.command-and-control`. Underscore forms such as `attack.initial_access` fail the
  ATT&CK check.
- `detection`: field-bound selections only, no keyword lists. Only fields listed for that
  contract entry. Fields in `contains_only_fields` may only use the `contains` modifier
  (optionally with `all`). No correlation rules and no deprecated aggregation syntax
  (`| count()` and similar).
- `falsepositives`: at least one entry.
- `references`: only real, working URLs. Leave the key out if you have none.

### ATT&CK version

`sigma check` validates tags against the current MITRE ATT&CK release, which pySigma downloads
at run time. ATT&CK v19 replaced the Defense Evasion tactic with **Stealth**
(`attack.stealth`) and **Defense Impairment** (`attack.defense-impairment`), and moved many
techniques (for example T1562.008 is now T1685.002). If a tag that used to pass starts failing
V017, check the technique on [attack.mitre.org](https://attack.mitre.org/) for its new ID.

## Severity levels

| Level | Meaning | Response |
|---|---|---|
| `critical` | High-confidence sign of active compromise or loss of security controls on a crown-jewel asset. | Respond now. |
| `high` | Likely malicious, low expected false-positive rate. | Triage the same day. |
| `medium` | Suspicious, needs context to judge. | Triage in the normal queue. |

We do not use `low` or `informational`. If a rule is not worth triaging at `medium`, it is a
hunting query, not a detection.

## Validator checks

`scripts/validate_rules.py` runs these checks. Each failure is printed as
`<path>: <CHECK_ID>: <message>`.

| ID | Check |
|---|---|
| V001 | File parses as YAML and holds exactly one document |
| V002 | All required keys present, no keys outside required + optional |
| V003 | `id` is a valid UUID version 4 and unique across the repo |
| V004 | `level` is in `allowed_levels` |
| V005 | `status` is in `allowed_status` |
| V006 | `date` (and `modified` if present) match `YYYY-MM-DD` and are real dates |
| V007 | `logsource` equals exactly one contract entry's `logsource` |
| V008 | Rule sits in that entry's `folder` (and directly inside one of the five folders) |
| V009 | File name follows the standard and starts with the contract key and `_`; only `.yml` files allowed |
| V010 | Tags: at least one valid tactic tag and one technique tag, lowercase, correct format |
| V011 | Every detection field is listed in the contract entry's `fields` |
| V012 | Fields in `contains_only_fields` use only `contains` (optionally with `all`) |
| V013 | No keyword (unbound) detection items |
| V014 | `falsepositives` is a non-empty list |
| V015 | `title` is unique across the repo |
| V016 | pySigma parses the rule without error |
| V017 | `sigma check` with every validator in `config/sigma_validation.yml` passes (needs internet) |

V016 and V017 only report on a file once every earlier check passes for it, so each problem
shows up once, under its most specific ID.

## Changing the contract

Adding a log source, adding a field, or changing a target in
`config/logsource_contract.yml` is a **contract change and needs approval**. The conversion
mappings in `pipelines/` and the generated translations depend on the contract: every field
listed must convert on every listed target. A field added without a matching mapping would
produce broken queries. Open a separate pull request for the contract change, explain the log
source and fields you need, and get approval from the owners of both rule authoring and
conversion before you write rules that use it.
