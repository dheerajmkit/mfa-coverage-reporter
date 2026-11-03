# mfa-coverage-reporter

Reads a CSV export of identity users and produces an MFA coverage report:
overall and per-department enrollment percentages, users stuck on weak
methods (SMS/voice only), dormant privileged accounts without MFA, and a
prioritized remediation list.

This is a **personal portfolio project** exploring identity-hygiene
reporting and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/users-sample.csv
```

Input CSV columns:

`username`, `department`, `mfa_enrolled`, `mfa_methods`, `last_auth`

- `mfa_enrolled`: `true`/`false`
- `mfa_methods`: semicolon-separated, e.g. `totp;push`, `sms`, or empty
- `last_auth`: `YYYY-MM-DD`, or empty when the user never authenticated

The exit code is `1` when dormant privileged accounts without MFA are
found and `0` otherwise, so the report can gate a review workflow.

Machine-readable output is available with `--json`:

```bash
python3 run.py --json samples/users-sample.csv > report.json
```

## Features

- **Enrollment math** — overall and per-department MFA enrollment
  percentages from a plain CSV export.
- **Weak-method detection** — flags users enrolled with SMS/voice only.
- **Dormancy analysis** — no auth in 90+ days (or never) counts as dormant.
- **Risk scoring** — every user gets a 0–100 score and a severity band:
  privileged + no MFA is critical, privileged + SMS-only is high,
  plain no-MFA is medium, SMS-only is low.
- **JSON output** (`--json`) with the full stats, remediation list, and
  per-user risk scores for piping into other tools.

## What it reports

- Overall MFA enrollment percentage
- Per-department enrollment breakdown
- Users enrolled with weak methods only (SMS/voice)
- Dormant privileged accounts without MFA (no auth in 90+ days)
- A prioritized remediation list (privileged + dormant first)
- Per-user risk scores with severity counts

"Privileged" here is a documented heuristic for the sample dataset:
departments `IT`, `Security`, `DevOps`, plus `svc-` service accounts. A
real deployment would source privilege from the IAM system itself.

## Layout

```
run.py                  # CLI: python3 run.py [--json] <users.csv>
mfa/
  __init__.py
  loader.py             # CSV loading into stable user dicts
  coverage.py           # enrollment math, dormancy, remediation ordering
  scoring.py            # per-user risk scores and severity bands
  report.py             # plain-text and JSON report rendering
samples/
  users-sample.csv      # 18 realistic fake users across 8 departments
```

## Roadmap

- **Day 3:** pytest unit tests, usage docs, and a sample remediation
  playbook.
