"""Security Alerting & Notification Module for Cloud Security Compliance Auditor."""

import os
import json
import sqlite3
import uuid
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from config import HISTORY_DB, ALERT_PRIORITIES, ALERT_CONSOLE_ENABLED, ALERT_EMAIL_ENABLED, ALERT_WEBHOOK_ENABLED
from src.remediation import get_remediation_guidance, enrich_result
from src.rules import ComplianceResult


@dataclass
class Alert:
    """Security alert data structure."""
    alert_id: str
    alert_key: str
    timestamp: str
    rule_id: str
    resource: str
    resource_type: str
    severity: str
    priority: str
    risk_score: int
    message: str
    remediation: str
    status: str = "OPEN"

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary representation."""
        return asdict(self)


class AlertStore:
    """Manages SQLite database storage for security alerts in history.db."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else HISTORY_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize security_alerts table in SQLite."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    alert_key TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_key_status 
                ON security_alerts(alert_key, status)
            """)
            conn.commit()
        finally:
            conn.close()

    def get_open_alert_by_key(self, alert_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve an OPEN alert matching the given alert_key, if any."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM security_alerts WHERE alert_key = ? AND status = 'OPEN' ORDER BY id DESC LIMIT 1",
                (alert_key,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def save_alert(self, alert: Alert) -> str:
        """Insert a new alert record into the database."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_alerts (
                    alert_id,
                    alert_key,
                    timestamp,
                    rule_id,
                    resource,
                    resource_type,
                    severity,
                    priority,
                    risk_score,
                    message,
                    remediation,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.alert_key,
                alert.timestamp,
                alert.rule_id,
                alert.resource,
                alert.resource_type,
                alert.severity,
                alert.priority,
                alert.risk_score,
                alert.message,
                alert.remediation,
                alert.status
            ))
            conn.commit()
            return alert.alert_id
        finally:
            conn.close()

    def resolve_missing_alerts(self, active_alert_keys: List[str]) -> List[str]:
        """Mark currently OPEN alerts as RESOLVED if their alert_key is not in active_alert_keys."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        resolved_ids = []
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT alert_id, alert_key FROM security_alerts WHERE status = 'OPEN'")
            open_alerts = cursor.fetchall()

            for row in open_alerts:
                if row["alert_key"] not in active_alert_keys:
                    cursor.execute(
                        "UPDATE security_alerts SET status = 'RESOLVED' WHERE alert_id = ?",
                        (row["alert_id"],)
                    )
                    resolved_ids.append(row["alert_id"])
            conn.commit()
            return resolved_ids
        finally:
            conn.close()

    def get_alerts(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve stored alerts sorted newest first, optionally filtered by status."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if status:
                query = "SELECT * FROM security_alerts WHERE status = ? ORDER BY id DESC"
                params = [status]
            else:
                query = "SELECT * FROM security_alerts ORDER BY id DESC"
                params = []

            if limit:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_alert_summary(self) -> Dict[str, int]:
        """Get counts of open, immediate, high, and resolved alerts."""
        alerts = self.get_alerts()
        open_alerts = [a for a in alerts if a.get("status") == "OPEN"]
        resolved_alerts = [a for a in alerts if a.get("status") == "RESOLVED"]

        immediate_open = [a for a in open_alerts if a.get("priority") == "Immediate"]
        high_open = [a for a in open_alerts if a.get("priority") == "High"]

        return {
            "total_alerts": len(alerts),
            "open_alerts": len(open_alerts),
            "immediate_alerts": len(immediate_open),
            "high_alerts": len(high_open),
            "resolved_alerts": len(resolved_alerts)
        }


class NotificationBackend:
    """Base interface for notification backends."""

    def send_alert(self, alert: Alert) -> bool:
        """Send notification for a security alert. Returns True if successful."""
        raise NotImplementedError


class ConsoleNotifier(NotificationBackend):
    """Outputs formatted security alert notifications to console / stdout."""

    def send_alert(self, alert: Alert) -> bool:
        prio = alert.priority.upper()
        print("\n==================================================")
        print(" SECURITY ALERT")
        print("==================================================")
        print(f"Priority         : {prio}")
        print(f"Rule ID          : {alert.rule_id}")
        print(f"Resource         : {alert.resource} ({alert.resource_type})")
        print(f"Severity         : {alert.severity}")
        print(f"Risk Score       : {alert.risk_score}")
        print(f"Message          : {alert.message}")
        print("\nRecommended Action:")
        print(f"  {alert.remediation}")
        print("==================================================\n")
        return True


class EmailNotifier(NotificationBackend):
    """Sends email notifications via SMTP if configured via environment variables."""

    def send_alert(self, alert: Alert) -> bool:
        enabled = os.getenv("ALERT_EMAIL_ENABLED", str(ALERT_EMAIL_ENABLED)).lower() in ("true", "1", "yes")
        if not enabled:
            return False

        host = os.getenv("SMTP_HOST")
        port = os.getenv("SMTP_PORT", "587")
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        from_addr = os.getenv("ALERT_FROM")
        to_addr = os.getenv("ALERT_TO")

        if not (host and username and password and from_addr and to_addr):
            print("[NOTICE] Email notification skipped: Missing required SMTP environment variables.", file=sys.stderr)
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText

            subject = f"[SECURITY ALERT] [{alert.priority.upper()}] {alert.rule_id} - {alert.resource}"
            body = (
                f"Security Alert Triggered:\n\n"
                f"Priority: {alert.priority}\n"
                f"Rule ID: {alert.rule_id}\n"
                f"Resource: {alert.resource} ({alert.resource_type})\n"
                f"Severity: {alert.severity}\n"
                f"Risk Score: {alert.risk_score}\n"
                f"Message: {alert.message}\n\n"
                f"Recommended Action:\n{alert.remediation}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = to_addr

            with smtplib.SMTP(host, int(port), timeout=10) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
            return True
        except Exception as e:
            print(f"[WARNING] Email notification failed: {e}", file=sys.stderr)
            return False


class WebhookNotifier(NotificationBackend):
    """Sends webhook notifications via HTTP POST if configured via environment variables."""

    def send_alert(self, alert: Alert) -> bool:
        enabled = os.getenv("ALERT_WEBHOOK_ENABLED", str(ALERT_WEBHOOK_ENABLED)).lower() in ("true", "1", "yes")
        webhook_url = os.getenv("ALERT_WEBHOOK_URL")

        if not enabled or not webhook_url:
            return False

        try:
            payload = json.dumps(alert.to_dict()).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 201, 202, 204)
        except Exception as e:
            print(f"[WARNING] Webhook notification failed: {e}", file=sys.stderr)
            return False


class AlertManager:
    """Coordinates security alert detection, deduplication, persistence, and notifications."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        priorities: Optional[List[str]] = None,
        notifiers: Optional[List[NotificationBackend]] = None
    ):
        self.store = AlertStore(db_path=db_path)
        self.priorities = priorities if priorities is not None else ALERT_PRIORITIES

        if notifiers is not None:
            self.notifiers = notifiers
        else:
            self.notifiers = []
            if ALERT_CONSOLE_ENABLED:
                self.notifiers.append(ConsoleNotifier())
            if ALERT_EMAIL_ENABLED:
                self.notifiers.append(EmailNotifier())
            if ALERT_WEBHOOK_ENABLED:
                self.notifiers.append(WebhookNotifier())

    def process_findings(self, results: List[Any]) -> Dict[str, Any]:
        """Process audit findings, generate new alerts for Immediate/High issues, and handle deduplication."""
        new_alerts: List[Alert] = []
        active_alert_keys: List[str] = []

        for item in results:
            if isinstance(item, ComplianceResult):
                res = enrich_result(item)
                res_dict = res.to_dict()
            elif isinstance(item, dict):
                res_dict = dict(item)
                if not res_dict.get("priority"):
                    guidance = get_remediation_guidance(
                        rule_id=res_dict.get("rule_id", ""),
                        severity=res_dict.get("severity", "HIGH"),
                        status=res_dict.get("status", "FAIL")
                    )
                    res_dict["priority"] = guidance.get("priority", "Unassigned")
                    res_dict["risk_score"] = guidance.get("risk_score", 0)
                    res_dict["remediation"] = guidance.get("remediation", "")
            else:
                continue

            if res_dict.get("status") != "FAIL":
                continue

            priority = res_dict.get("priority", "Unassigned")
            if priority not in self.priorities:
                continue

            rule_id = res_dict.get("rule_id", "UNKNOWN")
            resource = res_dict.get("resource", "Unknown")
            severity = res_dict.get("severity", "UNKNOWN")

            alert_key = f"{rule_id}:{resource}:{severity}:{priority}"
            active_alert_keys.append(alert_key)

            existing = self.store.get_open_alert_by_key(alert_key)
            if existing:
                # DUPLICATE -> Open alert already exists for this exact finding, skip creation
                continue

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_id = str(uuid.uuid4())[:8]

            alert = Alert(
                alert_id=alert_id,
                alert_key=alert_key,
                timestamp=timestamp,
                rule_id=rule_id,
                resource=resource,
                resource_type=res_dict.get("resource_type", "unknown"),
                severity=severity,
                priority=priority,
                risk_score=res_dict.get("risk_score", 0),
                message=res_dict.get("message", "Security compliance violation detected."),
                remediation=res_dict.get("remediation", "Review and remediate security configuration."),
                status="OPEN"
            )

            self.store.save_alert(alert)
            new_alerts.append(alert)

            for notifier in self.notifiers:
                try:
                    notifier.send_alert(alert)
                except Exception as e:
                    print(f"[WARNING] Notifier {notifier.__class__.__name__} error: {e}", file=sys.stderr)

        resolved_ids = self.store.resolve_missing_alerts(active_alert_keys)
        summary = self.store.get_alert_summary()

        return {
            "new_alerts": [a.to_dict() for a in new_alerts],
            "new_alerts_count": len(new_alerts),
            "resolved_missing_ids": resolved_ids,
            "summary": summary
        }

    def get_open_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all currently OPEN security alerts."""
        return self.store.get_alerts(status="OPEN")

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all historical and open security alerts."""
        return self.store.get_alerts()
