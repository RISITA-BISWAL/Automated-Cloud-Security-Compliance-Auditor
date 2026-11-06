"""Unit tests for historical compliance audit storage and trend tracking."""

from pathlib import Path
from tempfile import TemporaryDirectory
import pytest

from src.history import HistoricalAuditStore


class TestHistoricalAuditStore:
    """Test suite for HistoricalAuditStore logic using isolated temporary databases."""

    def test_database_initialization_and_table_creation(self):
        """Verify database and audit_history table are created upon initialization."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)
            assert db_file.exists()

            history = store.get_history()
            assert history == []

    def test_save_and_retrieve_audit_summary(self):
        """Verify saving an audit summary inserts a record that can be retrieved."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            stats = {
                "total_resources": 20,
                "total_checks": 35,
                "passed_checks": 22,
                "failed_checks": 13,
                "compliance_score": 62.86,
                "framework_summary": {
                    "framework": "CIS AWS Foundations Benchmark",
                    "controls_evaluated": 5,
                    "controls_passed": 0,
                    "controls_failed": 5,
                    "coverage_percentage": 0.0
                }
            }

            row_id = store.save_audit_summary(stats)
            assert row_id >= 1

            latest = store.get_latest_audit()
            assert latest is not None
            assert latest["resources_checked"] == 20
            assert latest["checks_performed"] == 35
            assert latest["passed_checks"] == 22
            assert latest["failed_checks"] == 13
            assert latest["compliance_score"] == 62.86
            assert latest["framework_coverage"] == 0.0

    def test_multiple_audit_records_retrieval(self):
        """Verify multiple audit entries are saved and retrieved newest first."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            store.save_audit_summary({"total_checks": 10, "passed_checks": 5, "compliance_score": 50.0})
            store.save_audit_summary({"total_checks": 10, "passed_checks": 6, "compliance_score": 60.0})

            history = store.get_history()
            assert len(history) == 2
            assert history[0]["compliance_score"] == 60.0
            assert history[1]["compliance_score"] == 50.0

    def test_trend_no_previous_audit(self):
        """Verify trend calculation when 0 or 1 audit exists."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            trend_empty = store.calculate_trend()
            assert trend_empty["trend_direction"] == "No previous data"
            assert trend_empty["current_score"] is None

            store.save_audit_summary({"compliance_score": 50.0})
            trend_single = store.calculate_trend()
            assert trend_single["trend_direction"] == "No previous data"
            assert trend_single["current_score"] == 50.0
            assert trend_single["previous_score"] is None

    def test_improving_trend(self):
        """Verify trend direction is Improving when score increases."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            store.save_audit_summary({"compliance_score": 50.0})
            store.save_audit_summary({"compliance_score": 60.0})

            trend = store.calculate_trend()
            assert trend["current_score"] == 60.0
            assert trend["previous_score"] == 50.0
            assert trend["score_change"] == 10.0
            assert trend["trend_direction"] == "Improving"

    def test_declining_trend(self):
        """Verify trend direction is Declining when score decreases."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            store.save_audit_summary({"compliance_score": 70.0})
            store.save_audit_summary({"compliance_score": 62.86})

            trend = store.calculate_trend()
            assert trend["current_score"] == 62.86
            assert trend["previous_score"] == 70.0
            assert trend["score_change"] == -7.14
            assert trend["trend_direction"] == "Declining"

    def test_stable_trend(self):
        """Verify trend direction is Stable when change is below threshold."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            store.save_audit_summary({"compliance_score": 62.86})
            store.save_audit_summary({"compliance_score": 62.86})

            trend = store.calculate_trend()
            assert trend["score_change"] == 0.0
            assert trend["trend_direction"] == "Stable"

    def test_database_persistence_across_instances(self):
        """Verify records persist across multiple HistoricalAuditStore instances on the same file."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store1 = HistoricalAuditStore(db_path=db_file)
            store1.save_audit_summary({"compliance_score": 75.0})

            store2 = HistoricalAuditStore(db_path=db_file)
            latest = store2.get_latest_audit()
            assert latest is not None
            assert latest["compliance_score"] == 75.0

    def test_invalid_or_empty_data_handling(self):
        """Verify store handles minimal/empty statistics dictionaries gracefully."""
        with TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "test_history.db"
            store = HistoricalAuditStore(db_path=db_file)

            row_id = store.save_audit_summary({})
            assert row_id >= 1
            latest = store.get_latest_audit()
            assert latest["compliance_score"] == 0.0
            assert latest["resources_checked"] == 0
