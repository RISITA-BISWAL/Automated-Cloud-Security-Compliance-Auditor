# Automated Cloud Security & Compliance Auditor

An automated, read-only cloud security auditing, compliance mapping, risk prioritization, historical trend tracking, and alert notification platform built with Python.

---

## 🏗️ Project Overview

The **Automated Cloud Security & Compliance Auditor** collects cloud configuration data from mock datasets or real AWS accounts (read-only), evaluates security compliance rules, maps violations to industry benchmarks (CIS AWS Foundations Benchmark), prioritizes risks, records compliance history in SQLite, generates deduplicated security alerts, exports reports (JSON/CSV), and visualizes results through an interactive Streamlit dashboard.

```text
       ┌──────────────────────────────┐
       │   Cloud Configuration Data   │
       │  (Mock Dataset / AWS APIs)   │
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │    Security Rules Engine     │
       │   (S3, EC2, RDS, IAM Checks) │
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │  Compliance Framework Map    │
       │  (CIS AWS Foundations v1.4)  │
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │  Risk Prioritization & KB    │
       │ (Immediate, High, Medium, Low)│
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌──────────────────────────────┐
       │   SQLite Alerting & History  │
       │ (Key Deduplication & Trends) │
       └──────────────┬───────────────┘
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
┌──────────────┐            ┌──────────────┐
│ Reports CLI  │            │  Streamlit   │
│ (JSON & CSV) │            │  Dashboard   │
└──────────────┘            └──────────────┘
```

---

## ✨ Features

- **Multi-Service Cloud Auditing**: Read-only inspection of Storage Buckets (S3), Virtual Machines (EC2), Databases (RDS), and IAM Configurations.
- **Security Compliance Engine**: Evaluates public access blocks/policies/ACLs, unencrypted storage/compute/database volumes, risky exposed management ports, public database access, missing backup retention, and un-MFA-protected privileged IAM accounts.
- **CIS AWS Foundations Benchmark Mapping**: Maps security rule violations directly to CIS AWS Foundations controls with framework coverage tracking.
- **Technical Compliance Scoring**: Calculates percentage compliance scores across total checks performed.
- **SQLite Compliance History & Trend Tracking**: Stores historical audit summaries in SQLite (`data/history.db`) and computes score changes and trend directions (Improving, Declining, Stable).
- **Risk Prioritization & Remediation Knowledge Base**: Categorizes violations by remediation priority (Immediate, High, Medium, Low) and provides risk scores (1-10) and actionable remediation steps.
- **Deduplicated Security Alerting Engine**: Identifies Immediate/High priority findings and generates alerts stored in SQLite with deterministic key deduplication (`rule_id:resource:severity:priority`) to prevent duplicate alerts for unchanged findings across audit runs.
- **Flexible Notification Backends**: Console notification output for local development, with optional Email (SMTP) and HTTP Webhook integrations via environment variables.
- **Multi-Format Reporting**: Automatically exports audit results to `data/reports/compliance_report.json` and `data/reports/compliance_report.csv`.
- **Interactive Streamlit Dashboard**: Web UI displaying Executive Metrics, Compliance Trends, CIS Control Status, Risk Prioritized Findings, Security Alerts, and Detailed Violations.
- **Comprehensive Test Suite**: Automated unit tests using mocked Boto3 calls and temporary SQLite databases.

---

## 🛡️ Active Security Rules Reference

| Rule ID | Rule Name | Target Resource | Severity | CIS Control | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `STORAGE-PUBLIC-001` | Public Storage Access | Storage Bucket | `HIGH` | CIS 2.1.5 | Detects buckets accessible publicly via PublicAccessBlock, Bucket Policies, or Bucket ACLs. |
| `IAM-MFA-001` | Privileged Account MFA | IAM User | `HIGH` | CIS 1.5 | Flags privileged users (Admin, Security Admin, `AdministratorAccess`) missing MFA. |
| `ENCRYPTION-001` | Data Encryption at Rest | Storage, VM, Database | `HIGH` | CIS 2.2.1 | Identifies unencrypted storage buckets, EBS volumes, and RDS database instances. |
| `NETWORK-PORT-001` | Exposed Risky Ports | Virtual Machine | `HIGH` / `MEDIUM` | CIS 5.1 | Detects publicly exposed risky administrative (SSH 22, RDP 3389) or service ports. |
| `DATABASE-PUBLIC-001` | Public Database Access | Database | `HIGH` | CIS 2.3.1 | Identifies RDS instances configured with `PubliclyAccessible=True`. |
| `DATABASE-BACKUP-001` | Database Backup Retention | Database | `MEDIUM` | CIS 2.3.2 | Flags RDS databases with `BackupRetentionPeriod=0` (disabled automated backups). |

---

## 🏛️ Architecture

```text
cloud-security-auditor/
├── config.py                 # Core project settings and rule severity definitions
├── run_auditor.py            # CLI entry point (audit, aws-audit, findings, history, alerts)
├── requirements.txt          # Verified project dependencies
├── README.md                 # Project documentation and guide
├── .gitignore                # Workspace ignore patterns
├── src/                      # Core auditor Python package
│   ├── models.py             # Data classes (StorageBucket, VirtualMachine, Database, IAMUser)
│   ├── collector.py          # MockCloudCollector (loads 20 mock resources)
│   ├── aws_collector.py      # AWSCloudCollector (Boto3 read-only S3, EC2, RDS, IAM)
│   ├── rules.py              # Compliance rules and ComplianceResult model
│   ├── auditor.py            # Auditor engine (executes rules across resources)
│   ├── compliance.py         # Framework compliance mapper (CIS AWS Foundations)
│   ├── history.py            # HistoricalAuditStore (SQLite history & trend analysis)
│   ├── remediation.py        # Risk prioritization knowledge base & remediation guidance
│   ├── alerts.py             # AlertManager, AlertStore (SQLite alerts & deduplication), Notifiers
│   ├── reporter.py           # Reporter (JSON & CSV report generation)
│   └── utils.py              # CLI terminal output formatting helpers
├── dashboard/
│   └── app.py                # Interactive Streamlit dashboard application
├── data/
│   ├── mock_cloud_config.json # 20 mock cloud resources dataset
│   ├── history.db            # Local SQLite database (history & security alerts) [Git-Ignored]
│   └── reports/              # Output directory for compliance reports [Git-Ignored]
└── tests/                    # Unit test suite
    ├── test_auditor.py
    ├── test_aws_collector.py
    ├── test_aws_ec2_collector.py
    ├── test_aws_iam_collector.py
    ├── test_aws_rds_collector.py
    ├── test_compliance.py
    ├── test_history.py
    ├── test_remediation.py
    ├── test_alerts.py
    ├── test_reporter.py
    └── test_rules.py
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- Python 3.10+ installed on your system.

### 2. Create and Activate Virtual Environment

**On Linux / macOS / WSL:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 CLI Usage Guide

The CLI tool `run_auditor.py` supports multiple auditing and inspection commands:

### 1. View General Help
```bash
python run_auditor.py --help
```

### 2. Run Mock Compliance Audit
Executes rules across 20 mock resources, records history, evaluates alerts, and exports reports:
```bash
python run_auditor.py audit
```

### 3. View Security Findings & Remediation Guidance
Displays prioritized failed security findings ordered by Immediate > High > Medium > Low with risk scores and remediation steps:
```bash
python run_auditor.py findings
```

### 4. View Historical Compliance Logs & Trends
Displays past audit runs from SQLite and calculates score trend changes:
```bash
python run_auditor.py history
```

### 5. View Active Security Alerts
Displays open Immediate and High priority security alerts:
```bash
python run_auditor.py alerts
```

To display all alerts including resolved historical alerts:
```bash
python run_auditor.py alerts --all
```

### 6. Run AWS Read-Only Audit (Optional)
Inspects live AWS resources using configured Boto3 credentials:
```bash
python run_auditor.py aws-audit --help
python run_auditor.py aws-audit --service all
python run_auditor.py aws-audit --service ec2 --region us-west-2
```
*Supported service options: `all`, `s3`, `ec2`, `rds`, `iam`.*

---

## 📊 Streamlit Dashboard

Launch the interactive web dashboard:
```bash
python -m streamlit run dashboard/app.py
```

Open your browser and navigate to:
```text
http://localhost:8501
```

### Dashboard Features:
- **Executive Overview**: Total Resources, Technical Compliance Score, Passed Checks, Failed Checks.
- **Compliance Trend**: Current Score, Previous Score, Score Change, Trend Direction (Improving, Declining, Stable), and Historical Trend Line Chart.
- **CIS Benchmark Summary**: Controls Evaluated, Controls Passed, Controls Failed, Framework Coverage %, and Control Status Breakdown table.
- **Security Alerts Overview**: Total Open Alerts, Immediate Alerts, High Alerts, Resolved Alerts, Active Alerts Table, and Alert Detail Expanders.
- **Security Findings & Remediation**: Priority metrics (Immediate, High, Medium, Low), Prioritized Findings Table, and Interactive Remediation Guidance Expanders.
- **Interactive Sidebar Filters**: Filter violations by Framework, Severity, Priority, Status, and Resource Type.

---

## 💡 Demonstration Workflow

Follow these steps to demonstrate the full capabilities of the auditor:

1. **Execute Mock Compliance Audit**:
   ```bash
   python run_auditor.py audit
   ```
   *Observables: Runs 35 checks across 20 mock resources, outputs technical compliance score (62.86%), exports JSON/CSV reports, and emits 13 initial security alerts.*

2. **Inspect Prioritized Findings**:
   ```bash
   python run_auditor.py findings
   ```
   *Observables: Displays 13 failed findings sorted by priority (8 Immediate, 5 High) with risk descriptions and remediation steps.*

3. **Check Compliance History & Trends**:
   ```bash
   python run_auditor.py history
   ```
   *Observables: Displays historical audit runs recorded in SQLite and score trend analysis.*

4. **Inspect Security Alerts**:
   ```bash
   python run_auditor.py alerts
   ```
   *Observables: Displays active open alerts. Re-running `python run_auditor.py audit` will demonstrate duplicate suppression (open alert count remains 13).*

5. **Launch Streamlit Dashboard**:
   ```bash
   python -m streamlit run dashboard/app.py
   ```
   *Observables: Opens web UI with executive overview, line charts, control breakdowns, and alert details.*

---

## 🔒 AWS Security Model & Safety

- **100% Read-Only Collection**: AWS collectors only invoke read-only API methods (`describe_*`, `list_*`, `get_*`). The application contains **zero** resource mutation APIs.
- **Advisory Remediation Model**: The system provides actionable guidance for human security engineers but does not perform automated infrastructure changes.
- **Zero Secrets Stored**: No AWS access keys, secret keys, SMTP passwords, or API tokens are hard-coded in the source code or committed to Git.
- **Safe Fallback**: If AWS credentials are missing or unconfigured, `aws-audit` fails gracefully with a user-friendly error message without throwing raw stack traces.

---

## 🧪 Testing & Verification

Run the full automated test suite using `pytest`:
```bash
python -m pytest -v
```

### Verified Test Status:
- **Total Tests**: `132`
- **Passed**: `132`
- **Failed**: `0`

The test suite validates collector logic using mocked Boto3 calls, rule evaluations, CIS mappings, SQLite history operations, alert key deduplication, notification backends, and report outputs without making external network calls or requiring AWS credentials.

---

## 🎓 Interview & Portfolio Summary

### Technologies Used
- **Language & Runtime**: Python 3.10+
- **Cloud Integration**: AWS SDK for Python (`boto3`, `botocore`)
- **Data Analytics & Storage**: `pandas`, SQLite 3 (`sqlite3`)
- **Web UI & Visualization**: `streamlit`
- **Testing & Quality**: `pytest`
- **Formats & Utilities**: JSON, CSV, `argparse`, `dataclasses`, `urllib`

### Key Engineering Concepts Demonstrated
1. **Multi-Service Read-Only Collector Architecture**: Decoupled mock vs live AWS data fetching using clean OOP data models.
2. **Deterministic Deduplication & Alert Lifecycle**: Uses composite hashing (`rule_id:resource:severity:priority`) in SQLite to track `OPEN` vs `RESOLVED` alert states across audit runs.
3. **Framework Mapping & Scoring**: Maps low-level rule evaluations to high-level CIS AWS Foundations Benchmark controls without altering raw rule scores.
4. **Risk-Based Prioritization**: Knowledge-base-driven prioritization (Immediate, High, Medium, Low) and risk scoring (1-10) for efficient security triage.
5. **Historical Trend Tracking**: SQLite-backed audit history calculation of moving score deltas and qualitative trends.

---

## ⚠️ Remaining Limitations

- **Mock Baseline**: Default offline mode relies on a sample 20-resource JSON configuration for demonstration purposes.
- **Supported AWS Services**: Read-only collection currently covers S3, EC2, RDS, and IAM. (Azure and GCP collectors are planned for future iterations).
- **Policy Simulation**: IAM rule checks inspect policy attachments and group memberships; full IAM condition evaluation or permission boundary simulation is not included.
- **Notification Backends**: Console notifications are active by default; Email (SMTP) and Webhooks require optional user-provided environment variables (`SMTP_HOST`, `ALERT_WEBHOOK_URL`).
