"""mfa-coverage-reporter: MFA coverage analysis from identity CSV exports."""

from .loader import load_users
from .coverage import compute_coverage, remediation_list
from .report import to_text, to_json
from .scoring import score_users, severity_counts

__all__ = ["load_users", "compute_coverage", "remediation_list",
           "to_text", "to_json", "score_users", "severity_counts"]
__version__ = "0.2.0"
