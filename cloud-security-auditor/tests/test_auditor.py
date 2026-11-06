"""Unit tests for the auditor module."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import StorageBucket, VirtualMachine, Database, IAMUser
from src.auditor import Auditor


class TestAuditor:
    """Tests for the Auditor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.resources = [
            StorageBucket(name="private-bucket", public_access=False, encrypted=True),
            StorageBucket(name="public-bucket", public_access=True, encrypted=True),
            VirtualMachine(name="secure-vm", encrypted=True, public_ip=False),
            VirtualMachine(name="exposed-vm", encrypted=True, public_ip=True, open_ports=[22]),
            Database(name="encrypted-db", encrypted=True, public_access=False),
            Database(name="unencrypted-db", encrypted=False, public_access=False),
            IAMUser(username="alice", role="admin", mfa_enabled=True),
            IAMUser(username="charlie", role="admin", mfa_enabled=False),
        ]
        self.auditor = Auditor(self.resources)

    def test_run_all_checks_returns_results(self):
        results = self.auditor.run_all_checks()
        assert len(results) > 0

    def test_total_checks_count(self):
        results = self.auditor.run_all_checks()
        # 2 storage x 2 rules + 2 vm x 2 rules + 2 database x 2 rules + 2 iam x 1 rule = 14
        assert len(results) == 14

    def test_statistics_structure(self):
        self.auditor.run_all_checks()
        stats = self.auditor.get_statistics()
        assert "total_resources" in stats
        assert "total_checks" in stats
        assert "passed_checks" in stats
        assert "failed_checks" in stats
        assert "compliance_score" in stats
        assert "violations_by_severity" in stats
        assert "violations_by_resource_type" in stats

    def test_compliance_score_calculation(self):
        self.auditor.run_all_checks()
        stats = self.auditor.get_statistics()
        expected_score = (stats["passed_checks"] / stats["total_checks"]) * 100
        assert stats["compliance_score"] == round(expected_score, 2)

    def test_violations_are_filtered(self):
        self.auditor.run_all_checks()
        violations = self.auditor.get_violations()
        assert all(v.status == "FAIL" for v in violations)

    def test_empty_resources(self):
        auditor = Auditor([])
        results = auditor.run_all_checks()
        assert len(results) == 0

        stats = auditor.get_statistics()
        assert stats["total_resources"] == 0
        assert stats["total_checks"] == 0
        assert stats["compliance_score"] == 0.0
