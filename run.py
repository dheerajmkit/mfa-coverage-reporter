#!/usr/bin/env python3
"""CLI entry point: analyze MFA coverage from an identity CSV export.

Usage:
    python3 run.py [--json] samples/users-sample.csv

Exits 1 when dormant privileged accounts without MFA are found,
0 otherwise.
"""
import sys

from mfa.loader import load_users
from mfa.coverage import compute_coverage, remediation_list
from mfa.report import to_text, to_json
from mfa.scoring import score_users, severity_counts


def main(argv):
    flags = [a for a in argv[1:] if a.startswith("-")]
    args = [a for a in argv[1:] if not a.startswith("-")]
    if len(args) != 1 or any(f != "--json" for f in flags):
        print("usage: python3 run.py [--json] <users.csv>", file=sys.stderr)
        return 2
    users = load_users(args[0])
    stats = compute_coverage(users)
    remediation = remediation_list(users)
    scored = score_users(users)
    if "--json" in flags:
        print(to_json(stats, remediation, scored), end="")
    else:
        print(to_text(stats, remediation), end="")
        print("## Risk scores")
        for item in scored:
            if item["severity"] == "ok":
                continue
            reasons = "; ".join(item["reasons"])
            print(f"- {item['username']} [{item['severity']}] "
                  f"score={item['score']} — {reasons}")
        counts = severity_counts(scored)
        summary = ", ".join(f"{sev}: {counts[sev]}" for sev in counts)
        print(f"\nSeverity counts — {summary}")
    return 1 if stats["dormant_privileged_no_mfa"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
