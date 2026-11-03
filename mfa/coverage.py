"""MFA coverage math: enrollment rates, weak methods, dormancy.

"Privileged" is a documented heuristic for the sample dataset: the
departments IT, Security and DevOps, plus usernames starting with "svc-".
A real deployment would source privilege from the IAM system itself.
"""
from datetime import date

STRONG_METHODS = {"totp", "push", "fido2", "webauthn", "hardware-key",
                  "authenticator-app"}
WEAK_METHODS = {"sms", "voice"}

PRIVILEGED_DEPARTMENTS = {"IT", "Security", "DevOps"}

DORMANT_DAYS = 90


def is_privileged(user):
    """True for users in privileged departments or svc- service accounts."""
    return (user["department"] in PRIVILEGED_DEPARTMENTS
            or user["username"].startswith("svc-"))


def is_dormant(user, today=None):
    """True when the user never authenticated or last_auth is older than 90 days."""
    today = today or date.today()
    raw = user["last_auth"]
    if not raw:
        return True
    try:
        year, month, day = (int(part) for part in raw.split("-"))
        last = date(year, month, day)
    except ValueError:
        return True  # unparseable date: treat as unknown and therefore dormant
    return (today - last).days > DORMANT_DAYS


def weak_only(user):
    """True when enrolled but every registered method is a weak one (SMS/voice)."""
    methods = set(user["mfa_methods"])
    return bool(methods) and methods <= WEAK_METHODS


def _pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


def compute_coverage(users, today=None):
    """Return coverage stats overall and per department."""
    enrolled = [u for u in users if u["mfa_enrolled"]]
    stats = {
        "total": len(users),
        "enrolled": len(enrolled),
        "enrollment_pct": _pct(len(enrolled), len(users)),
        "weak_only": sorted(u["username"] for u in users if weak_only(u)),
        "no_mfa": sorted(u["username"] for u in users if not u["mfa_enrolled"]),
        "dormant_privileged_no_mfa": sorted(
            u["username"] for u in users
            if is_privileged(u) and not u["mfa_enrolled"] and is_dormant(u, today)
        ),
        "departments": {},
    }
    for user in users:
        dept = stats["departments"].setdefault(
            user["department"], {"total": 0, "enrolled": 0})
        dept["total"] += 1
        if user["mfa_enrolled"]:
            dept["enrolled"] += 1
    for dept in stats["departments"].values():
        dept["enrollment_pct"] = _pct(dept["enrolled"], dept["total"])
    return stats


def _remediation_priority(user, today):
    if is_privileged(user) and not user["mfa_enrolled"] and is_dormant(user, today):
        return (0, "privileged, dormant, no MFA enrolled")
    if is_privileged(user) and not user["mfa_enrolled"]:
        return (1, "privileged, no MFA enrolled")
    if is_privileged(user) and weak_only(user):
        return (2, "privileged, weak MFA methods only (SMS/voice)")
    if not user["mfa_enrolled"]:
        return (3, "no MFA enrolled")
    if weak_only(user):
        return (4, "weak MFA methods only (SMS/voice)")
    return (5, "covered")


def remediation_list(users, today=None):
    """Prioritized (username, reason) remediation list, highest risk first."""
    ranked = []
    for user in users:
        priority, reason = _remediation_priority(user, today)
        if priority < 5:
            ranked.append((priority, user["username"], reason))
    ranked.sort()
    return [(username, reason) for _, username, reason in ranked]
