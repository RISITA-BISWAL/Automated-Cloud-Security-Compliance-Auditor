"""Reporter module for generating compliance reports."""

import json
import csv
from pathlib import Path
from typing import Dict, Any, List

from config import REPORTS_DIR


class Reporter:
    """Generates compliance reports in multiple formats."""

    def __init__(self, output_dir: Path = REPORTS_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        statistics: Dict[str, Any],
        violations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate complete compliance report."""
        report = {
            "executive_summary": {
                "total_resources": statistics["total_resources"],
                "total_checks": statistics["total_checks"],
                "passed_checks": statistics["passed_checks"],
                "failed_checks": statistics["failed_checks"],
                "compliance_score": statistics["compliance_score"]
            },
            "severity_breakdown": statistics["violations_by_severity"],
            "resource_type_breakdown": statistics["violations_by_resource_type"],
            "detailed_violations": violations
        }

        if "framework_summary" in statistics:
            report["framework_summary"] = statistics["framework_summary"]

        if "remediation_summary" in statistics:
            report["remediation_summary"] = statistics["remediation_summary"]

        if "trend" in statistics:
            report["trend"] = statistics["trend"]

        if "alert_summary" in statistics:
            report["alert_summary"] = statistics["alert_summary"]

        return report

    def save_json_report(self, report: Dict[str, Any]) -> str:
        """Save report as JSON file."""
        file_path = self.output_dir / "compliance_report.json"
        with open(file_path, "w") as f:
            json.dump(report, f, indent=2)
        return str(file_path)

    def save_csv_report(self, violations: List[Dict[str, Any]]) -> str:
        """Save violations as CSV file."""
        file_path = self.output_dir / "compliance_report.csv"
        fieldnames = ["rule_id", "resource", "resource_type", "status", "severity", "framework", "control_id", "control_title", "message", "priority", "risk_score", "risk_description", "remediation"]

        if not violations:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(fieldnames)
                writer.writerow(["No violations found"] + [""] * (len(fieldnames) - 1))
            return str(file_path)

        with open(file_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(violations)

        return str(file_path)

    def generate_and_save(
        self,
        statistics: Dict[str, Any],
        violations: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate and save reports in all formats."""
        report = self.generate_report(statistics, violations)

        saved_files = []
        saved_files.append(self.save_json_report(report))
        saved_files.append(self.save_csv_report(violations))

        return saved_files
