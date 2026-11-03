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

## What it reports (day 1)

- Overall MFA enrollment percentage
- Per-department enrollment breakdown
- Users enrolled with weak methods only (SMS/voice)
- Dormant privileged accounts without MFA (no auth in 90+ days)
- A prioritized remediation list (privileged + dormant first)

"Privileged" here is a documented heuristic for the sample dataset:
departments `IT`, `Security`, `DevOps`, plus `svc-` service accounts. A
real deployment would source privilege from the IAM system itself.

## Layout

```
run.py                  # CLI: python3 run.py <users.csv>
mfa/
  __init__.py
  loader.py             # CSV loading into stable user dicts
  coverage.py           # enrollment math, dormancy, remediation ordering
  report.py             # plain-text report rendering
samples/
  users-sample.csv      # 18 realistic fake users across 8 departments
```

## Roadmap

- **Day 2:** numeric risk scoring per user, richer per-department
  breakdowns, and JSON output (`--json`).
- **Day 3:** pytest unit tests, usage docs, and a sample remediation
  playbook.
