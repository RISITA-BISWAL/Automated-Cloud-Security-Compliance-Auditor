#!/usr/bin/env python3
"""CLI entry point for the Cloud Security Compliance Auditor."""

import argparse
import sys

from config import CONFIG_FILE
from src.collector import MockCloudCollector
from src.auditor import Auditor
from src.reporter import Reporter
from src.utils import print_summary
from src.history import HistoricalAuditStore
from src.alerts import AlertManager


def run_audit(config_path: str) -> None:
    """Run the full audit pipeline using mock data."""
    collector = MockCloudCollector(config_path)
    resources = collector.get_resources()

    auditor = Auditor(resources)
    results = auditor.run_all_checks()
    statistics = auditor.get_statistics()
    violations = [r.to_dict() for r in auditor.get_violations()]

    history_store = HistoricalAuditStore()
    history_store.save_audit_summary(statistics)
    statistics["trend"] = history_store.calculate_trend()

    alert_mgr = AlertManager()
    alert_res = alert_mgr.process_findings(results)
    statistics["alert_summary"] = alert_res["summary"]

    reporter = Reporter()
    saved_files = reporter.generate_and_save(statistics, violations)

    print_summary(statistics, saved_files)


def run_aws_audit(region: str = None, service: str = "all") -> None:
    """Run the full audit pipeline using AWS data (S3, EC2, RDS, IAM, or all)."""
    try:
        from src.aws_collector import AWSCloudCollector

        collector = AWSCloudCollector(region=region)
        resources = collector.collect_all(service=service)

        auditor = Auditor(resources)
        results = auditor.run_all_checks()
        statistics = auditor.get_statistics()
        violations = [r.to_dict() for r in auditor.get_violations()]

        history_store = HistoricalAuditStore()
        history_store.save_audit_summary(statistics)
        statistics["trend"] = history_store.calculate_trend()

        alert_mgr = AlertManager()
        alert_res = alert_mgr.process_findings(results)
        statistics["alert_summary"] = alert_res["summary"]

        reporter = Reporter()
        saved_files = reporter.generate_and_save(statistics, violations)

        print_summary(statistics, saved_files)
    except (ConnectionError, ImportError) as e:
        print(f"\n[ERROR] AWS Audit Failed: {e}", file=sys.stderr)
        sys.exit(1)


def run_history() -> None:
    """Display audit history and compliance trends."""
    store = HistoricalAuditStore()
    history = store.get_history()
    trend = store.calculate_trend()

    print("\n==================================================")
    print(" COMPLIANCE AUDIT HISTORY")
    print("==================================================")

    if not history:
        print("No historical audits available.")
        print("==================================================\n")
        return

    print(f"{'Date':<20} {'Checks':<8} {'Passed':<8} {'Failed':<8} {'Score':<8}")
    print("-" * 54)
    for record in reversed(history):
        ts = str(record.get("timestamp", ""))[:16]
        checks = record.get("checks_performed", 0)
        passed = record.get("passed_checks", 0)
        failed = record.get("failed_checks", 0)
        score = f"{record.get('compliance_score', 0.0):.2f}%"
        print(f"{ts:<20} {checks:<8} {passed:<8} {failed:<8} {score:<8}")

    print("\n--------------------------------------------------")
    cur_score = f"{trend['current_score']:.2f}%" if trend.get('current_score') is not None else "N/A"
    prev_score = f"{trend['previous_score']:.2f}%" if trend.get('previous_score') is not None else "N/A"

    change_val = trend.get('score_change')
    if change_val is not None:
        change_str = f"{'+' if change_val > 0 else ''}{change_val:.2f} percentage points"
    else:
        change_str = "N/A"

    print(f"Current Score : {cur_score}")
    print(f"Previous Score: {prev_score}")
    print(f"Change        : {change_str}")
    print(f"Trend         : {trend.get('trend_direction', 'No previous data')}")
    print("==================================================\n")


def run_findings() -> None:
    """Display prioritized security findings and remediation guidance."""
    import json
    from config import REPORTS_DIR
    from src.remediation import PRIORITY_ORDER

    report_path = REPORTS_DIR / "compliance_report.json"
    if not report_path.exists():
        run_audit(str(CONFIG_FILE))

    with open(report_path, "r") as f:
        report = json.load(f)

    violations = report.get("detailed_violations", [])
    failed_violations = [v for v in violations if v.get("status") == "FAIL"]

    print("\n==================================================")
    print(" SECURITY FINDINGS & REMEDIATION")
    print("==================================================")

    if not failed_violations:
        print("No security findings requiring remediation.")
        print("==================================================\n")
        return

    def sort_key(v):
        priority_val = PRIORITY_ORDER.get(v.get("priority", "Unassigned"), 0)
        return (priority_val, v.get("risk_score", 0), v.get("severity", "LOW"))

    sorted_violations = sorted(failed_violations, key=sort_key, reverse=True)

    rem_summary = report.get("remediation_summary", {})
    imm = rem_summary.get("Immediate", 0)
    high = rem_summary.get("High", 0)
    med = rem_summary.get("Medium", 0)
    low = rem_summary.get("Low", 0)

    print(f"Summary: Immediate: {imm} | High: {high} | Medium: {med} | Low: {low}")
    print("--------------------------------------------------")

    for i, v in enumerate(sorted_violations, 1):
        prio = (v.get("priority") or "UNASSIGNED").upper()
        rule_id = v.get("rule_id", "UNKNOWN")
        resource = v.get("resource", "Unknown")
        resource_type = v.get("resource_type", "")
        severity = v.get("severity", "UNKNOWN")
        risk_score = v.get("risk_score", 0)
        risk_desc = v.get("risk_description", "No risk description available.")
        remediation = v.get("remediation", "No remediation steps available.")
        control_id = v.get("control_id", "")
        control_title = v.get("control_title", "")
        framework = v.get("framework", "")

        print(f"\n{i}. [{prio}] {rule_id} (Risk Score: {risk_score})")
        print(f"Resource          : {resource} ({resource_type})")
        print(f"Severity          : {severity}")
        print(f"Risk              : {risk_desc}")
        print(f"Recommended Action: {remediation}")
        if control_id and control_id != "Unmapped":
            print(f"Framework Control : {framework} {control_id} - {control_title}")
        print("-" * 50)

    print("==================================================\n")


def run_alerts(show_all: bool = False) -> None:
    """Display active or historical security alerts."""
    alert_mgr = AlertManager()
    alerts = alert_mgr.get_all_alerts() if show_all else alert_mgr.get_open_alerts()
    summary = alert_mgr.store.get_alert_summary()

    print("\n==================================================")
    print(" SECURITY ALERTS")
    print("==================================================")
    print(f"Open Alerts: {summary['open_alerts']}")
    print(f"Resolved Alerts: {summary['resolved_alerts']}")
    print("--------------------------------------------------")

    if not alerts:
        print("No active security alerts." if not show_all else "No security alerts found in history.")
        print("==================================================\n")
        return

    priority_order = {"Immediate": 4, "High": 3, "Medium": 2, "Low": 1, "Unassigned": 0}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (priority_order.get(a.get("priority"), 0), a.get("risk_score", 0), a.get("timestamp", "")),
        reverse=True
    )

    for a in sorted_alerts:
        prio = str(a.get("priority", "UNASSIGNED")).upper()
        status_tag = f" [{a.get('status')}]" if show_all else ""
        rule_id = a.get("rule_id", "UNKNOWN")
        resource = a.get("resource", "Unknown")
        resource_type = a.get("resource_type", "")
        severity = a.get("severity", "UNKNOWN")
        risk_score = a.get("risk_score", 0)
        message = a.get("message", "")
        remediation = a.get("remediation", "")

        print(f"\n[{prio}]{status_tag} {rule_id}")
        print(f"Resource         : {resource} ({resource_type})")
        print(f"Severity         : {severity}")
        print(f"Risk Score       : {risk_score}")
        print(f"\nRisk:")
        print(f"{message}")
        print(f"\nRecommended Action:")
        print(f"{remediation}")
        print("-" * 50)

    print("==================================================\n")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud Security Compliance Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_auditor.py audit
  python run_auditor.py audit --config data/mock_cloud_config.json
  python run_auditor.py aws-audit
  python run_auditor.py aws-audit --service ec2 --region us-west-2
  python run_auditor.py aws-audit --service rds
  python run_auditor.py aws-audit --service iam
  python run_auditor.py history
  python run_auditor.py findings
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    audit_parser = subparsers.add_parser("audit", help="Run compliance audit using mock data")
    audit_parser.add_argument(
        "--config",
        default=str(CONFIG_FILE),
        help="Path to cloud configuration file"
    )

    aws_parser = subparsers.add_parser(
        "aws-audit",
        help="Run compliance audit using AWS (read-only)"
    )
    aws_parser.add_argument(
        "--region",
        default=None,
        help="AWS region to query (optional, uses AWS config default if omitted)"
    )
    aws_parser.add_argument(
        "--service",
        choices=["all", "s3", "ec2", "rds", "iam"],
        default="all",
        help="AWS service to audit (all, s3, ec2, rds, or iam)"
    )

    subparsers.add_parser(
        "history",
        help="View historical compliance audit logs and trend analysis"
    )

    subparsers.add_parser(
        "findings",
        help="View prioritized security findings and remediation guidance"
    )

    alerts_parser = subparsers.add_parser(
        "alerts",
        help="View security alerts and notifications"
    )
    alerts_parser.add_argument(
        "--all",
        action="store_true",
        help="Display all alerts including resolved alerts"
    )

    args = parser.parse_args()

    if args.command == "audit":
        run_audit(args.config)
    elif args.command == "aws-audit":
        run_aws_audit(region=args.region, service=args.service)
    elif args.command == "history":
        run_history()
    elif args.command == "findings":
        run_findings()
    elif args.command == "alerts":
        run_alerts(show_all=args.all)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
