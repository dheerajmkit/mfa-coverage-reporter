"""Plain-text MFA coverage report rendering."""


def to_text(stats, remediation):
    """Render the coverage stats and remediation list as plain text."""
    lines = ["# MFA coverage report", ""]
    lines.append(f"Users analyzed : {stats['total']}")
    lines.append(
        f"MFA enrolled   : {stats['enrolled']} ({stats['enrollment_pct']}%)")
    lines.append("")
    lines.append("## Per-department enrollment")
    for dept in sorted(stats["departments"]):
        entry = stats["departments"][dept]
        lines.append(
            f"- {dept}: {entry['enrolled']}/{entry['total']} "
            f"({entry['enrollment_pct']}%)")
    lines.append("")
    lines.append(f"## Weak methods only (SMS/voice) — {len(stats['weak_only'])}")
    for name in stats["weak_only"]:
        lines.append(f"- {name}")
    lines.append("")
    lines.append("## Dormant privileged accounts without MFA — "
                 f"{len(stats['dormant_privileged_no_mfa'])}")
    for name in stats["dormant_privileged_no_mfa"]:
        lines.append(f"- {name}")
    lines.append("")
    lines.append(f"## Prioritized remediation list — {len(remediation)}")
    for rank, (username, reason) in enumerate(remediation, start=1):
        lines.append(f"{rank}. {username} — {reason}")
    return "\n".join(lines) + "\n"
