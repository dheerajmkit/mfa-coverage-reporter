"""Per-user risk scoring for MFA gaps.

Severity ladder (highest first):
    critical — privileged account with no MFA enrolled
    high     — privileged account with weak methods only, or any dormant
               account with no MFA
    medium   — non-privileged account with no MFA
    low      — non-privileged account with weak methods only
    ok       — enrolled with at least one strong method
"""
from .coverage import is_privileged, is_dormant, weak_only

SEVERITIES = ("critical", "high", "medium", "low", "ok")

SCORES = {"critical": 100, "high": 75, "medium": 50, "low": 25, "ok": 0}


def score_user(user, today=None):
    """Return a (score, severity, reasons) tuple for one user."""
    reasons = []
    if is_privileged(user):
        reasons.append("privileged account")
    if not user["mfa_enrolled"]:
        reasons.append("no MFA enrolled")
        if is_dormant(user, today):
            reasons.append("dormant account")
        if is_privileged(user):
            severity = "critical"
        elif is_dormant(user, today):
            severity = "high"
        else:
            severity = "medium"
    elif weak_only(user):
        reasons.append("weak MFA methods only (SMS/voice)")
        severity = "high" if is_privileged(user) else "low"
    else:
        severity = "ok"
    return SCORES[severity], severity, reasons


def score_users(users, today=None):
    """Score every user; returns a list of dicts sorted by score, then name."""
    scored = []
    for user in users:
        score, severity, reasons = score_user(user, today)
        scored.append({
            "username": user["username"],
            "department": user["department"],
            "score": score,
            "severity": severity,
            "reasons": reasons,
        })
    scored.sort(key=lambda item: (-item["score"], item["username"]))
    return scored


def severity_counts(scored):
    """Count scored users per severity band."""
    counts = {sev: 0 for sev in SEVERITIES}
    for item in scored:
        counts[item["severity"]] += 1
    return counts
