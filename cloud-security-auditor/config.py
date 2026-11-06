"""Configuration settings for the Cloud Security Compliance Auditor."""

from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
CONFIG_FILE = DATA_DIR / "mock_cloud_config.json"
HISTORY_DB = DATA_DIR / "history.db"

# Report settings
REPORT_FORMATS = ["json", "csv"]

# Compliance rule settings
PRIVILEGED_ROLES = ["admin", "administrator", "security_admin"]

ALLOWED_PORTS = [80, 443, 8080, 8443, 9090, 3000]

RISKY_PORTS = [22, 3389, 3306, 1433, 5432, 27017]

# Severity levels
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

# Rule severity mapping
RULE_SEVERITY = {
    "STORAGE-PUBLIC-001": "HIGH",
    "IAM-MFA-001": "HIGH",
    "ENCRYPTION-001": "HIGH",
    "NETWORK-PORT-001": "MEDIUM",
    "DATABASE-PUBLIC-001": "HIGH",
    "DATABASE-BACKUP-001": "MEDIUM"
}

# Security Alerting & Notification Settings
ALERT_PRIORITIES = ["Immediate", "High"]
ALERT_CONSOLE_ENABLED = True
ALERT_EMAIL_ENABLED = False
ALERT_WEBHOOK_ENABLED = False

