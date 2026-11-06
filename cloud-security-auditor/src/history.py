"""Historical compliance audit storage and trend analysis module."""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from config import HISTORY_DB


class HistoricalAuditStore:
    """Manages SQLite database storage for compliance audit history and trends."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else HISTORY_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create audit_history table if it does not exist."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    resources_checked INTEGER NOT NULL,
                    checks_performed INTEGER NOT NULL,
                    passed_checks INTEGER NOT NULL,
                    failed_checks INTEGER NOT NULL,
                    compliance_score REAL NOT NULL,
                    framework TEXT,
                    controls_evaluated INTEGER,
                    controls_passed INTEGER,
                    controls_failed INTEGER,
                    framework_coverage REAL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def save_audit_summary(self, statistics: Dict[str, Any]) -> int:
        """Save an audit summary to the historical database."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        resources_checked = statistics.get("total_resources", 0)
        checks_performed = statistics.get("total_checks", 0)
        passed_checks = statistics.get("passed_checks", 0)
        failed_checks = statistics.get("failed_checks", 0)
        compliance_score = statistics.get("compliance_score", 0.0)

        framework_summary = statistics.get("framework_summary", {})
        framework = framework_summary.get("framework", "CIS AWS Foundations Benchmark")
        controls_evaluated = framework_summary.get("controls_evaluated", 0)
        controls_passed = framework_summary.get("controls_passed", 0)
        controls_failed = framework_summary.get("controls_failed", 0)
        framework_coverage = framework_summary.get("coverage_percentage", 0.0)

        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_history (
                    timestamp,
                    resources_checked,
                    checks_performed,
                    passed_checks,
                    failed_checks,
                    compliance_score,
                    framework,
                    controls_evaluated,
                    controls_passed,
                    controls_failed,
                    framework_coverage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                resources_checked,
                checks_performed,
                passed_checks,
                failed_checks,
                compliance_score,
                framework,
                controls_evaluated,
                controls_passed,
                controls_failed,
                framework_coverage
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve historical audit summaries sorted newest first."""
        query = "SELECT * FROM audit_history ORDER BY id DESC"
        params = []
        if limit:
            query += " LIMIT ?"
            params.append(limit)

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_latest_audit(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent historical audit record."""
        history = self.get_history(limit=1)
        return history[0] if history else None

    def calculate_trend(self) -> Dict[str, Any]:
        """Calculate compliance trend metrics between current and previous audits."""
        history = self.get_history(limit=2)
        total_count = len(self.get_history())

        if not history:
            return {
                "current_score": None,
                "previous_score": None,
                "score_change": None,
                "trend_direction": "No previous data",
                "history_count": 0
            }

        latest = history[0]
        current_score = round(float(latest["compliance_score"]), 2)

        if len(history) < 2:
            return {
                "current_score": current_score,
                "previous_score": None,
                "score_change": None,
                "trend_direction": "No previous data",
                "history_count": 1
            }

        previous = history[1]
        previous_score = round(float(previous["compliance_score"]), 2)
        score_change = round(current_score - previous_score, 2)

        if abs(score_change) < 0.01:
            trend_direction = "Stable"
        elif score_change > 0:
            trend_direction = "Improving"
        else:
            trend_direction = "Declining"

        return {
            "current_score": current_score,
            "previous_score": previous_score,
            "score_change": score_change,
            "trend_direction": trend_direction,
            "history_count": total_count
        }
