"""Unit test suite for Security Alerting & Notification System."""

import os
import sqlite3
import pytest
from pathlib import Path

from src.alerts import (
    Alert,
    AlertStore,
    AlertManager,
    ConsoleNotifier,
    EmailNotifier,
    WebhookNotifier
)
from src.rules import ComplianceResult
from config import ALERT_PRIORITIES


@pytest.fixture
def temp_db(tmp_path):
    """Provide a temporary database file path for isolated testing."""
    return tmp_path / "test_alerts.db"


class TestAlertStore:
    """Test suite for SQLite AlertStore database operations."""

    def test_alert_creation_and_storage(self, temp_db):
        store = AlertStore(db_path=temp_db)
        alert = Alert(
            alert_id="alt-001",
            alert_key="IAM-MFA-001:admin-user:HIGH:Immediate",
            timestamp="2026-08-29 12:00:00",
            rule_id="IAM-MFA-001",
            resource="admin-user",
            resource_type="iam_user",
            severity="HIGH",
            priority="Immediate",
            risk_score=8,
            message="Privileged account missing MFA",
            remediation="Enable MFA",
            status="OPEN"
        )
        saved_id = store.save_alert(alert)
        assert saved_id == "alt-001"

    def test_alert_retrieval(self, temp_db):
        store = AlertStore(db_path=temp_db)
        alert = Alert(
            alert_id="alt-002",
            alert_key="STORAGE-PUBLIC-001:public-bucket:HIGH:Immediate",
            timestamp="2026-08-29 12:05:00",
            rule_id="STORAGE-PUBLIC-001",
            resource="public-bucket",
            resource_type="storage_bucket",
            severity="HIGH",
            priority="Immediate",
            risk_score=8,
            message="Public storage bucket detected",
            remediation="Block public access",
            status="OPEN"
        )
        store.save_alert(alert)
        alerts = store.get_alerts(status="OPEN")
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "alt-002"
        assert alerts[0]["resource"] == "public-bucket"

    def test_alert_persistence_after_restart(self, temp_db):
        store1 = AlertStore(db_path=temp_db)
        alert = Alert(
            alert_id="alt-persist",
            alert_key="ENCRYPTION-001:data-disk:HIGH:High",
            timestamp="2026-08-29 12:10:00",
            rule_id="ENCRYPTION-001",
            resource="data-disk",
            resource_type="virtual_machine",
            severity="HIGH",
            priority="High",
            risk_score=8,
            message="Unencrypted disk",
            remediation="Enable encryption",
            status="OPEN"
        )
        store1.save_alert(alert)

        # Re-open database connection with a new instance
        store2 = AlertStore(db_path=temp_db)
        alerts = store2.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "alt-persist"

    def test_resolve_missing_alerts(self, temp_db):
        store = AlertStore(db_path=temp_db)
        alert1 = Alert("a1", "KEY-1", "2026-08-29", "R1", "res1", "vm", "HIGH", "High", 8, "msg", "rem", "OPEN")
        alert2 = Alert("a2", "KEY-2", "2026-08-29", "R2", "res2", "vm", "HIGH", "High", 8, "msg", "rem", "OPEN")
        store.save_alert(alert1)
        store.save_alert(alert2)

        # KEY-1 remains active, KEY-2 disappears
        resolved_ids = store.resolve_missing_alerts(["KEY-1"])
        assert resolved_ids == ["a2"]

        open_alerts = store.get_alerts(status="OPEN")
        assert len(open_alerts) == 1
        assert open_alerts[0]["alert_id"] == "a1"

        resolved_alerts = store.get_alerts(status="RESOLVED")
        assert len(resolved_alerts) == 1
        assert resolved_alerts[0]["alert_id"] == "a2"


class TestAlertManager:
    """Test suite for AlertManager business logic and deduplication."""

    def test_immediate_finding_creates_alert(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="IAM-MFA-001",
            resource="admin-user",
            resource_type="iam_user",
            status="FAIL",
            severity="HIGH",
            message="Missing MFA"
        )
        res.priority = "Immediate"
        res.risk_score = 8
        res.remediation = "Enable MFA"

        res_dict = mgr.process_findings([res])
        assert res_dict["new_alerts_count"] == 1
        assert res_dict["new_alerts"][0]["rule_id"] == "IAM-MFA-001"
        assert res_dict["new_alerts"][0]["priority"] == "Immediate"

    def test_high_finding_creates_alert(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="ENCRYPTION-001",
            resource="web-vm",
            resource_type="virtual_machine",
            status="FAIL",
            severity="HIGH",
            message="Unencrypted disk"
        )
        res.priority = "High"
        res.risk_score = 8
        res.remediation = "Enable encryption"

        res_dict = mgr.process_findings([res])
        assert res_dict["new_alerts_count"] == 1
        assert res_dict["new_alerts"][0]["rule_id"] == "ENCRYPTION-001"
        assert res_dict["new_alerts"][0]["priority"] == "High"

    def test_medium_finding_does_not_create_alert(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="DATABASE-BACKUP-001",
            resource="app-db",
            resource_type="database",
            status="FAIL",
            severity="MEDIUM",
            message="No backup retention"
        )

        res_dict = mgr.process_findings([res])
        assert res_dict["new_alerts_count"] == 0
        assert mgr.get_open_alerts() == []

    def test_low_finding_does_not_create_alert(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="TEST-LOW-001",
            resource="test-res",
            resource_type="test",
            status="FAIL",
            severity="LOW",
            message="Low priority issue"
        )
        res.priority = "Low"
        res.risk_score = 2
        res.remediation = "Fix low issue"

        res_dict = mgr.process_findings([res])
        assert res_dict["new_alerts_count"] == 0

    def test_duplicate_finding_does_not_create_duplicate_alert(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="IAM-MFA-001",
            resource="admin-user",
            resource_type="iam_user",
            status="FAIL",
            severity="HIGH",
            message="Missing MFA"
        )

        # First run creates 1 alert
        res1 = mgr.process_findings([res])
        assert res1["new_alerts_count"] == 1

        # Second run with exact same unchanged finding creates 0 alerts (DUPLICATE)
        res2 = mgr.process_findings([res])
        assert res2["new_alerts_count"] == 0
        assert len(mgr.get_open_alerts()) == 1

    def test_different_resources_create_separate_alerts(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res1 = ComplianceResult(
            rule_id="IAM-MFA-001", resource="user-1", resource_type="iam_user",
            status="FAIL", severity="HIGH", message="No MFA"
        )
        res2 = ComplianceResult(
            rule_id="IAM-MFA-001", resource="user-2", resource_type="iam_user",
            status="FAIL", severity="HIGH", message="No MFA"
        )

        res_dict = mgr.process_findings([res1, res2])
        assert res_dict["new_alerts_count"] == 2
        assert len(mgr.get_open_alerts()) == 2

    def test_different_rules_create_separate_alerts(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res1 = ComplianceResult(
            rule_id="IAM-MFA-001", resource="app-res", resource_type="iam_user",
            status="FAIL", severity="HIGH", message="No MFA"
        )
        res2 = ComplianceResult(
            rule_id="STORAGE-PUBLIC-001", resource="app-res", resource_type="storage_bucket",
            status="FAIL", severity="HIGH", message="Public bucket"
        )

        res_dict = mgr.process_findings([res1, res2])
        assert res_dict["new_alerts_count"] == 2
        assert len(mgr.get_open_alerts()) == 2

    def test_resolved_alert_handling(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        res = ComplianceResult(
            rule_id="IAM-MFA-001", resource="temp-user", resource_type="iam_user",
            status="FAIL", severity="HIGH", message="No MFA"
        )

        # Step 1: Finding exists -> alert created
        mgr.process_findings([res])
        assert len(mgr.get_open_alerts()) == 1

        # Step 2: Finding disappears -> alert resolved
        mgr.process_findings([])
        assert len(mgr.get_open_alerts()) == 0
        all_alerts = mgr.get_all_alerts()
        assert len(all_alerts) == 1
        assert all_alerts[0]["status"] == "RESOLVED"

    def test_unknown_invalid_finding_handling(self, temp_db):
        mgr = AlertManager(db_path=temp_db, notifiers=[])
        # Invalid / non-dict / non-ComplianceResult inputs should be ignored gracefully
        res_dict = mgr.process_findings([None, "invalid_string", 12345])
        assert res_dict["new_alerts_count"] == 0

    def test_configuration_behavior(self, temp_db):
        # Custom priorities: include Medium
        mgr = AlertManager(db_path=temp_db, priorities=["Immediate", "High", "Medium"], notifiers=[])
        res = ComplianceResult(
            rule_id="DATABASE-BACKUP-001", resource="prod-db", resource_type="database",
            status="FAIL", severity="MEDIUM", message="No backups"
        )

        res_dict = mgr.process_findings([res])
        assert res_dict["new_alerts_count"] == 1


class TestNotifications:
    """Test suite for notification backends and error handling."""

    def test_console_notifier(self, capsys):
        notifier = ConsoleNotifier()
        alert = Alert(
            alert_id="alt-c",
            alert_key="KEY-C",
            timestamp="2026-08-29",
            rule_id="IAM-MFA-001",
            resource="console-user",
            resource_type="iam_user",
            severity="HIGH",
            priority="Immediate",
            risk_score=8,
            message="No MFA",
            remediation="Enable MFA",
            status="OPEN"
        )
        success = notifier.send_alert(alert)
        assert success is True

        captured = capsys.readouterr()
        assert "SECURITY ALERT" in captured.out
        assert "IAM-MFA-001" in captured.out
        assert "console-user" in captured.out

    def test_email_notifier_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ALERT_EMAIL_ENABLED", raising=False)
        notifier = EmailNotifier()
        alert = Alert("a", "k", "ts", "r", "res", "type", "HIGH", "High", 8, "msg", "rem")
        assert notifier.send_alert(alert) is False

    def test_email_notifier_missing_credentials_fails_gracefully(self, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "true")
        monkeypatch.delenv("SMTP_HOST", raising=False)
        notifier = EmailNotifier()
        alert = Alert("a", "k", "ts", "r", "res", "type", "HIGH", "High", 8, "msg", "rem")
        assert notifier.send_alert(alert) is False

    def test_webhook_notifier_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ALERT_WEBHOOK_ENABLED", raising=False)
        notifier = WebhookNotifier()
        alert = Alert("a", "k", "ts", "r", "res", "type", "HIGH", "High", 8, "msg", "rem")
        assert notifier.send_alert(alert) is False

    def test_read_only_aws_safety(self):
        # Verify that no AWS write operations exist in src.alerts
        import src.alerts as alerts_mod
        code_text = Path(alerts_mod.__file__).read_text()
        forbidden_keywords = ["create_bucket", "delete_bucket", "put_bucket", "modify_instance", "delete_instance"]
        for kw in forbidden_keywords:
            assert kw not in code_text
