"""Utility functions for the Cloud Security Compliance Auditor."""

from pathlib import Path
from typing import List

from config import SEVERITY_LEVELS


def format_severity_counts(severity_counts: dict) -> str:
    """Format severity counts for display."""
    lines = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            lines.append(f"  {severity}: {count}")
    return "\n".join(lines)


def print_summary(statistics: dict, saved_files: List[str]) -> None:
    """Print audit summary to console."""
    print("\n" + "=" * 50)
    print(" CLOUD SECURITY COMPLIANCE AUDITOR")
    print("=" * 50)

    print(f"\nResources checked : {statistics['total_resources']}")
    print(f"Checks performed  : {statistics['total_checks']}")
    print(f"Passed checks     : {statistics['passed_checks']}")
    print(f"Failed checks     : {statistics['failed_checks']}")

    print(f"\nCompliance Score  : {statistics['compliance_score']}%")

    severity_text = format_severity_counts(statistics["violations_by_severity"])
    if severity_text:
        print(f"\nViolations by Severity:")
        print(severity_text)

    print("\nReport generated:")
    for file_path in saved_files:
        print(f"  {file_path}")

    print("=" * 50 + "\n")
