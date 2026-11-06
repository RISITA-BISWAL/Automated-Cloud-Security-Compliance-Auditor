"""Unit tests for compliance framework mapping module."""

import json
import csv
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

from src.compliance import (
    COMPLIANCE_MAPPINGS,
    get_rule_compliance_mapping,
    enrich_compliance_result,
    calculate_framework_summary
)
from src.models import StorageBucket
from src.rules import check_storage_public_access, ComplianceResult
from src.auditor import Auditor
from src.reporter import Reporter


class TestComplianceMapping:
    """Test suite for compliance framework mappings."""

    def test_mappings_exist_for_all_rules(self):
        """Verify each supported security rule has a compliance mapping."""
        supported_rules = [
            "STORAGE-PUBLIC-001",
            "IAM-MFA-001",
            "ENCRYPTION-001",
            "NETWORK-PORT-001",
            "DATABASE-PUBLIC-001",
            "DATABASE-BACKUP-001"
        ]
        for rule_id in supported_rules:
            assert rule_id in COMPLIANCE_MAPPINGS
            mapping = COMPLIANCE_MAPPINGS[rule_id]
            assert "framework" in mapping
            assert "control_id" in mapping
            assert "control_title" in mapping
            assert "compliance_category" in mapping

    def test_unknown_rule_returns_unmapped(self):
        """Verify unknown rule ID returns Unmapped fallback."""
        mapping = get_rule_compliance_mapping("UNKNOWN-RULE-999")
        assert mapping["framework"] == "Unmapped"
        assert mapping["control_id"] == "Unmapped"
        assert mapping["control_title"] == "Unmapped Control"
        assert mapping["description"] == "Framework mapping: pending verification"

    def test_result_enrichment(self):
        """Verify compliance result is enriched with framework metadata."""
        raw_result = ComplianceResult(
            rule_id="STORAGE-PUBLIC-001",
            resource="my-bucket",
            resource_type="storage",
            status="PASS",
            severity="HIGH",
            message="Bucket is private"
        )
        enriched = enrich_compliance_result(raw_result)
        assert enriched.framework == "CIS AWS Foundations Benchmark"
        assert enriched.control_id == "2.1.5"
        assert enriched.control_title == "Ensure S3 Bucket Public Access Block is enabled"
        assert enriched.compliance_category == "Storage Security"

    def test_framework_summary_statistics(self):
        """Verify framework statistics are correctly calculated from actual results."""
        results = [
            ComplianceResult("STORAGE-PUBLIC-001", "b1", "storage", "PASS", "HIGH", "ok", "CIS AWS Foundations Benchmark", "2.1.5", "Block Public Access", "Storage Security"),
            ComplianceResult("STORAGE-PUBLIC-001", "b2", "storage", "FAIL", "HIGH", "public", "CIS AWS Foundations Benchmark", "2.1.5", "Block Public Access", "Storage Security"),
            ComplianceResult("ENCRYPTION-001", "b1", "storage", "PASS", "HIGH", "encrypted", "CIS AWS Foundations Benchmark", "2.2.1", "Data Encryption", "Data Protection"),
            ComplianceResult("ENCRYPTION-001", "b2", "storage", "PASS", "HIGH", "encrypted", "CIS AWS Foundations Benchmark", "2.2.1", "Data Encryption", "Data Protection")
        ]

        summary = calculate_framework_summary(results)
        assert summary["controls_evaluated"] == 2
        assert summary["controls_passed"] == 1  # 2.2.1 passed all
        assert summary["controls_failed"] == 1  # 2.1.5 failed b2
        assert summary["coverage_percentage"] == 50.0

    def test_auditor_preserves_technical_compliance_score(self):
        """Verify technical compliance score remains based on checks passed / total checks."""
        resources = [
            StorageBucket(name="b1", public_access=False, encrypted=True),
            StorageBucket(name="b2", public_access=True, encrypted=False)
        ]
        auditor = Auditor(resources)
        results = auditor.run_all_checks()
        stats = auditor.get_statistics()

        assert stats["total_checks"] == 4
        assert stats["passed_checks"] == 2
        assert stats["failed_checks"] == 2
        assert stats["compliance_score"] == 50.0
        assert "framework_summary" in stats

    def test_json_report_contains_framework_fields(self):
        """Verify JSON report includes framework summary and findings metadata."""
        stats = {
            "total_resources": 1,
            "total_checks": 1,
            "passed_checks": 1,
            "failed_checks": 0,
            "compliance_score": 100.0,
            "violations_by_severity": {},
            "violations_by_resource_type": {},
            "framework_summary": {
                "framework": "CIS AWS Foundations Benchmark",
                "controls_evaluated": 1,
                "controls_passed": 1,
                "controls_failed": 0,
                "coverage_percentage": 100.0
            }
        }
        violations = [
            {
                "rule_id": "IAM-MFA-001",
                "resource": "admin",
                "resource_type": "iam",
                "status": "FAIL",
                "severity": "HIGH",
                "message": "No MFA",
                "framework": "CIS AWS Foundations Benchmark",
                "control_id": "1.5",
                "control_title": "MFA for privileged access"
            }
        ]

        with TemporaryDirectory() as tmp_dir:
            reporter = Reporter(output_dir=Path(tmp_dir))
            json_path = reporter.save_json_report(reporter.generate_report(stats, violations))
            with open(json_path, "r") as f:
                data = json.load(f)

            assert "framework_summary" in data
            assert data["framework_summary"]["coverage_percentage"] == 100.0
            assert data["detailed_violations"][0]["control_id"] == "1.5"

    def test_csv_report_contains_framework_columns(self):
        """Verify CSV report includes Framework, Control ID, and Control Title columns."""
        violations = [
            {
                "rule_id": "DATABASE-PUBLIC-001",
                "resource": "db1",
                "resource_type": "database",
                "status": "FAIL",
                "severity": "HIGH",
                "message": "DB Publicly accessible",
                "framework": "CIS AWS Foundations Benchmark",
                "control_id": "2.3.1",
                "control_title": "RDS Database Public Access"
            }
        ]

        with TemporaryDirectory() as tmp_dir:
            reporter = Reporter(output_dir=Path(tmp_dir))
            csv_path = reporter.save_csv_report(violations)
            with open(csv_path, "r") as f:
                reader = csv.reader(f)
                rows = list(reader)

            header = rows[0]
            assert "framework" in header
            assert "control_id" in header
            assert "control_title" in header
            assert rows[1][header.index("control_id")] == "2.3.1"
