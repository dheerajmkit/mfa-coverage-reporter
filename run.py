#!/usr/bin/env python3
"""CLI entry point: analyze MFA coverage from an identity CSV export.

Usage:
    python3 run.py samples/users-sample.csv

Exits 1 when dormant privileged accounts without MFA are found,
0 otherwise.
"""
import sys

from mfa.loader import load_users
from mfa.coverage import compute_coverage, remediation_list
from mfa.report import to_text


def main(argv):
    if len(argv) != 2:
        print("usage: python3 run.py <users.csv>", file=sys.stderr)
        return 2
    users = load_users(argv[1])
    stats = compute_coverage(users)
    remediation = remediation_list(users)
    print(to_text(stats, remediation), end="")
    return 1 if stats["dormant_privileged_no_mfa"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
