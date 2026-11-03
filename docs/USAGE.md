# Usage guide

mfa-coverage-reporter is a personal portfolio project: an MFA coverage
reporter in pure Python 3 (standard library only). It has never been
deployed at any employer — it exists to demonstrate identity-hygiene
reporting and security-automation skills.

## Install

Nothing to install beyond Python 3. Clone the repo and run from its root:

```bash
git clone https://github.com/dheerajmkit/mfa-coverage-reporter.git
cd mfa-coverage-reporter
```

## Input format

A CSV export with these columns:

```
username,department,mfa_enrolled,mfa_methods,last_auth
```

- `mfa_enrolled`: `true`/`false` (also accepts `1`/`0`, `yes`/`no`)
- `mfa_methods`: semicolon-separated, e.g. `totp;push`, `sms`, or empty
- `last_auth`: `YYYY-MM-DD`, or empty when the user never authenticated

## Basic report

```bash
python3 run.py samples/users-sample.csv
```

Exit code `1` means dormant privileged accounts without MFA were found;
`0` means none. The report shows overall and per-department enrollment,
weak-method-only users, dormant privileged accounts without MFA, and a
prioritized remediation list, followed by per-user risk scores.

## JSON mode

For piping into other tools:

```bash
python3 run.py --json samples/users-sample.csv > report.json
```

The JSON payload contains `summary`, `departments`, `weak_only`,
`no_mfa`, `dormant_privileged_no_mfa`, `remediation`, and `risk_scores`.

## Risk scoring

| Severity | Meaning | Score |
| -------- | ------- | ----- |
| critical | privileged account, no MFA | 100 |
| high | privileged + SMS-only, or dormant + no MFA | 75 |
| medium | no MFA enrolled | 50 |
| low | SMS/voice methods only | 25 |
| ok | enrolled with a strong method | 0 |

"Privileged" is a heuristic for the sample dataset (IT, Security, DevOps
departments plus `svc-` accounts). Point it at a real IAM export by
mapping the privilege column into `department` or adjusting
`PRIVILEGED_DEPARTMENTS` in `mfa/coverage.py`.

## Method strength

Strong: `totp`, `push`, `fido2`, `webauthn`, `hardware-key`,
`authenticator-app`. Weak: `sms`, `voice`. Edit `STRONG_METHODS` /
`WEAK_METHODS` in `mfa/coverage.py` to match your policy.

## Remediation playbook

See `examples/remediation-playbook.md` for a sample step-by-step
workflow built on the report output.

## Tests

```bash
python3 -m pytest tests/ -v
```
