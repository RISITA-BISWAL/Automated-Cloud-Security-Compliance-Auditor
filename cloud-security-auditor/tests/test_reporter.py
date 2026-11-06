"""Unit tests for the reporter module."""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.reporter import Reporter


class TestReporter:
    """Tests for the Reporter class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.reporter = Reporter(output_dir=Path("/tmp/test_reports"))
        self.statistics = {
            "total_resources": 20,
            "total_checks": 30,
            "passed_checks": 25,
            "failed_checks": 5,
            "compliance_score": 83.33,
            "violations_by_severity": {"HIGH": 3, "MEDIUM": 2},
            "violations_by_resource_type": {"storage": 2, "vm": 1, "database": 1, "iam": 1}
        }
        self.violations = [
            {
                "rule_id": "STORAGE-PUBLIC-001",
                "resource": "public-bucket",
                "resource_type": "storage",
                "status": "FAIL",
                "severity": "HIGH",
                "message": "Storage bucket 'public-bucket' is publicly accessible."
            }
        ]

    def test_generate_report_structure(self):
        report = self.reporter.generate_report(self.statistics, self.violations)
        assert "executive_summary" in report
        assert "severity_breakdown" in report
        assert "resource_type_breakdown" in report
        assert "detailed_violations" in report

    def test_executive_summary_values(self):
        report = self.reporter.generate_report(self.statistics, self.violations)
        summary = report["executive_summary"]
        assert summary["total_resources"] == 20
        assert summary["compliance_score"] == 83.33

    def test_save_json_report(self):
        report = self.reporter.generate_report(self.statistics, self.violations)
        file_path = self.reporter.save_json_report(report)
        assert Path(file_path).exists()

        with open(file_path, "r") as f:
            loaded = json.load(f)
        assert loaded["executive_summary"]["total_resources"] == 20

    def test_save_csv_report(self):
        file_path = self.reporter.save_csv_report(self.violations)
        assert Path(file_path).exists()

    def test_save_csv_report_empty_violations(self):
        file_path = self.reporter.save_csv_report([])
        assert Path(file_path).exists()

    def test_generate_and_save(self):
        saved_files = self.reporter.generate_and_save(self.statistics, self.violations)
        assert len(saved_files) == 2
        for file_path in saved_files:
            assert Path(file_path).exists()
