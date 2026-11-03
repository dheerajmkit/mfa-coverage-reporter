# Sample MFA remediation playbook

A worked example of turning the reporter's output into an action plan.
All names are fictional.

## 1. Generate the report

```bash
python3 run.py --json quarterly-export.csv > mfa-report.json
```

## 2. Triage the criticals first

Dormant privileged accounts without MFA are the highest blast radius:
an attacker who compromises one gets elevated access with no second
factor. For each account in `dormant_privileged_no_mfa`:

1. Confirm with the account owner (or their manager) whether the account
   is still needed.
2. If not needed: disable it and revoke its entitlements.
3. If needed: enforce MFA enrollment before re-enabling access, and
   rotate any long-lived credentials.

## 3. Enforce phishing-resistant MFA for privileged users

Accounts flagged `high` (privileged + SMS-only) should move off SMS/voice
to TOTP at minimum, FIDO2/WebAuthn where the device fleet supports it.
Track migration per department with the `departments` breakdown.

## 4. Drive the long tail

`medium` and `low` findings are bulk enrollment work: send the
per-department enrollment percentages to each department lead, set a
target date, and re-run the report weekly until enrollment crosses your
policy threshold.

## 5. Re-run and diff

```bash
python3 run.py --json quarterly-export.csv > mfa-report-new.json
diff <(python3 -c "import json;print(json.load(open('mfa-report.json'))['summary'])") \
     <(python3 -c "import json;print(json.load(open('mfa-report-new.json'))['summary'])")
```

Enrollment should only move in one direction.
