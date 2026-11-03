"""Load identity user exports (CSV) into stable user dicts.

Expected columns:
    username, department, mfa_enrolled, mfa_methods, last_auth

- ``mfa_enrolled``: "true"/"false" (case-insensitive; also accepts 1/0/yes/no)
- ``mfa_methods``: semicolon-separated list, e.g. "totp;push", "sms", ""
- ``last_auth``: YYYY-MM-DD, or empty when the user never authenticated
"""
import csv

REQUIRED_COLUMNS = ("username", "department", "mfa_enrolled",
                    "mfa_methods", "last_auth")

TRUE_VALUES = {"true", "1", "yes", "y"}
FALSE_VALUES = {"false", "0", "no", "n", ""}


def _parse_bool(raw):
    value = (raw or "").strip().lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ValueError(f"unrecognized boolean value: {raw!r}")


def _parse_methods(raw):
    return [m.strip().lower() for m in (raw or "").split(";") if m.strip()]


def load_users(path):
    """Read a CSV export and return a list of user dicts."""
    users = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(
                "CSV is missing required columns: " + ", ".join(missing))
        for lineno, row in enumerate(reader, start=2):
            username = (row.get("username") or "").strip()
            if not username:
                raise ValueError(f"row {lineno}: username is required")
            users.append({
                "username": username,
                "department": (row.get("department") or "").strip() or "Unknown",
                "mfa_enrolled": _parse_bool(row.get("mfa_enrolled")),
                "mfa_methods": _parse_methods(row.get("mfa_methods")),
                "last_auth": (row.get("last_auth") or "").strip(),
            })
    return users
