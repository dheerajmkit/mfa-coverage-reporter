"""Unit tests for the MFA coverage reporter.

Run with:  python3 -m pytest tests/ -v   (from the repo root)
"""
import json
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mfa.loader import load_users
from mfa.coverage import (compute_coverage, remediation_list, is_privileged,
                          is_dormant, weak_only)
from mfa.scoring import score_user, score_users, severity_counts
from mfa.report import to_text, to_json

SAMPLE = os.path.join(os.path.dirname(__file__), "..",
                      "samples", "users-sample.csv")
TODAY = date(2026, 10, 13)


def _user(**overrides):
    base = {"username": "testuser", "department": "Engineering",
            "mfa_enrolled": True, "mfa_methods": ["totp"],
            "last_auth": "2026-10-12"}
    base.update(overrides)
    return base


def test_loader_reads_sample_csv():
    users = load_users(SAMPLE)
    assert len(users) == 18
    assert users[0]["username"] == "jdoe"
    assert users[0]["mfa_methods"] == ["totp", "push"]


def test_loader_rejects_missing_column(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("username,department\njdoe,Engineering\n")
    try:
        load_users(str(bad))
    except ValueError as exc:
        assert "missing required columns" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_coverage_enrollment_pct():
    users = load_users(SAMPLE)
    stats = compute_coverage(users, TODAY)
    assert stats["total"] == 18
    assert stats["enrolled"] == 11
    assert stats["enrollment_pct"] == 61.1


def test_weak_only_detection():
    assert weak_only(_user(mfa_methods=["sms"]))
    assert weak_only(_user(mfa_methods=["sms", "voice"]))
    assert not weak_only(_user(mfa_methods=["sms", "totp"]))
    assert not weak_only(_user(mfa_methods=[]))


def test_privileged_heuristic():
    assert is_privileged(_user(department="IT"))
    assert is_privileged(_user(department="Security"))
    assert is_privileged(_user(username="svc-backup", department="Sales"))
    assert not is_privileged(_user(department="Engineering"))


def test_dormant_detection():
    assert is_dormant(_user(last_auth="2026-06-01"), TODAY)
    assert not is_dormant(_user(last_auth="2026-10-01"), TODAY)
    assert is_dormant(_user(last_auth=""), TODAY)


def test_dormant_privileged_no_mfa():
    users = load_users(SAMPLE)
    stats = compute_coverage(users, TODAY)
    assert stats["dormant_privileged_no_mfa"] == ["hchen", "lwang",
                                                 "svc-backup"]


def test_remediation_lists_critical_first():
    users = load_users(SAMPLE)
    remediation = remediation_list(users, TODAY)
    assert remediation[0][0] == "hchen"
    assert "privileged, dormant, no MFA" in remediation[0][1]
    assert all(u["username"] != "jdoe" for u, _ in
               [(dict(username=n), r) for n, r in remediation])


def test_scoring_severities():
    assert score_user(_user(department="IT", mfa_enrolled=False,
                            mfa_methods=[], last_auth="2026-01-01"),
                      TODAY)[1] == "critical"
    assert score_user(_user(department="IT", mfa_methods=["sms"]),
                      TODAY)[1] == "high"
    assert score_user(_user(mfa_enrolled=False, mfa_methods=[],
                            last_auth="2026-10-01"), TODAY)[1] == "medium"
    assert score_user(_user(mfa_methods=["sms"]), TODAY)[1] == "low"
    assert score_user(_user(), TODAY)[1] == "ok"


def test_scoring_sorted_by_score():
    users = load_users(SAMPLE)
    scored = score_users(users, TODAY)
    scores = [s["score"] for s in scored]
    assert scores == sorted(scores, reverse=True)
    assert scored[0]["severity"] == "critical"


def test_severity_counts_add_up():
    users = load_users(SAMPLE)
    counts = severity_counts(score_users(users, TODAY))
    assert sum(counts.values()) == 18


def test_text_report_sections():
    users = load_users(SAMPLE)
    text = to_text(compute_coverage(users, TODAY),
                   remediation_list(users, TODAY))
    assert "# MFA coverage report" in text
    assert "## Per-department enrollment" in text
    assert "## Prioritized remediation list" in text


def test_json_report_parses():
    users = load_users(SAMPLE)
    payload = to_json(compute_coverage(users, TODAY),
                      remediation_list(users, TODAY),
                      score_users(users, TODAY))
    data = json.loads(payload)
    assert data["summary"]["total"] == 18
    assert len(data["risk_scores"]) == 18
