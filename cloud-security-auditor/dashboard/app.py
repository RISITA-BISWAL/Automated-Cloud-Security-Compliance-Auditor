"""Streamlit dashboard for Cloud Security Compliance Auditor."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd

from config import REPORTS_DIR


def load_report():
    """Load the compliance report JSON file."""
    report_path = REPORTS_DIR / "compliance_report.json"
    if not report_path.exists():
        return None
    with open(report_path, "r") as f:
        return json.load(f)


def main():
    """Main dashboard application."""
    st.set_page_config(
        page_title="Cloud Security Compliance Auditor",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ Cloud Security Compliance Auditor")

    report = load_report()

    if report is None:
        st.warning("No compliance report found. Run the auditor first.")
        st.code("python run_auditor.py audit", language="bash")
        return

    summary = report["executive_summary"]
    framework_summary = report.get("framework_summary", {})

    st.header("Executive Overview")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Resources", summary["total_resources"])
    col2.metric("Compliance Score", f"{summary['compliance_score']}%")
    col3.metric("Passed Checks", summary["passed_checks"])
    col4.metric("Failed Checks", summary["failed_checks"])

    # Historical Compliance Trend Section
    try:
        from src.history import HistoricalAuditStore
        history_store = HistoricalAuditStore()
        trend_info = history_store.calculate_trend()
        history_records = history_store.get_history()
    except Exception:
        trend_info = report.get("trend", {})
        history_records = []

    st.header("📈 Compliance Trend")
    tcol1, tcol2, tcol3, tcol4 = st.columns(4)

    cur_score_val = trend_info.get('current_score')
    cur_score_str = f"{cur_score_val:.2f}%" if cur_score_val is not None else f"{summary['compliance_score']}%"
    
    prev_score_val = trend_info.get('previous_score')
    prev_score_str = f"{prev_score_val:.2f}%" if prev_score_val is not None else "N/A"

    change_val = trend_info.get('score_change')
    if change_val is not None:
        change_str = f"{'+' if change_val > 0 else ''}{change_val:.2f}%"
    else:
        change_str = "N/A"

    direction = trend_info.get('trend_direction', 'No previous data')
    if direction == "Improving":
        direction_icon = "↑ Improving"
    elif direction == "Declining":
        direction_icon = "↓ Declining"
    elif direction == "Stable":
        direction_icon = "→ Stable"
    else:
        direction_icon = "No previous data"

    tcol1.metric("Current Score", cur_score_str)
    tcol2.metric("Previous Score", prev_score_str)
    tcol3.metric("Score Change", change_str)
    tcol4.metric("Trend", direction_icon)

    st.subheader("Historical Compliance Score Trend")
    if len(history_records) >= 2:
        h_df = pd.DataFrame(list(reversed(history_records)))
        h_df["Date"] = h_df["timestamp"].apply(lambda x: str(x)[:16])
        st.line_chart(h_df.set_index("Date")["compliance_score"])
    else:
        st.info("Not enough historical data to display a trend line chart. Run more audits to build history.")

    if history_records:
        st.subheader("Audit History Log")
        h_display_df = pd.DataFrame(history_records)
        cols_to_show = [c for c in ["timestamp", "checks_performed", "passed_checks", "failed_checks", "compliance_score", "framework_coverage"] if c in h_display_df.columns]
        st.dataframe(h_display_df[cols_to_show], use_container_width=True)

    if framework_summary:
        st.header(f"Compliance Framework: {framework_summary.get('framework', 'CIS AWS Foundations Benchmark')}")
        fcol1, fcol2, fcol3, fcol4 = st.columns(4)
        fcol1.metric("Controls Evaluated", framework_summary.get("controls_evaluated", 0))
        fcol2.metric("Controls Passed", framework_summary.get("controls_passed", 0))
        fcol3.metric("Controls Failed", framework_summary.get("controls_failed", 0))
        fcol4.metric("Framework Coverage", f"{framework_summary.get('coverage_percentage', 0.0)}%")

        cstatus = framework_summary.get("control_status", {})
        if cstatus:
            c_df = pd.DataFrame(list(cstatus.values()))
            st.subheader("Control Status Breakdown")
            st.dataframe(
                c_df[["control_id", "control_title", "category", "status", "failed_checks", "total_checks"]],
                use_container_width=True
            )

    st.header("Security Status")
    col1, col2 = st.columns(2)
    with col1:
        st.success(f"✅ Passed: {summary['passed_checks']}")
    with col2:
        st.error(f"❌ Failed: {summary['failed_checks']}")

    # Security Alerts Section
    st.header("🚨 Security Alerts")
    try:
        from src.alerts import AlertStore
        alert_store = AlertStore()
        alerts = alert_store.get_alerts()
        alert_summary_data = alert_store.get_alert_summary()
    except Exception:
        alerts = []
        alert_summary_data = report.get("alert_summary", {})

    acol1, acol2, acol3, acol4 = st.columns(4)
    acol1.metric("Total Open Alerts", alert_summary_data.get("open_alerts", 0))
    acol2.metric("Immediate Alerts", alert_summary_data.get("immediate_alerts", 0))
    acol3.metric("High Alerts", alert_summary_data.get("high_alerts", 0))
    acol4.metric("Resolved Alerts", alert_summary_data.get("resolved_alerts", 0))

    if alerts:
        alerts_df = pd.DataFrame(alerts)
        priority_order = {"Immediate": 4, "High": 3, "Medium": 2, "Low": 1, "Unassigned": 0}
        alerts_df["prio_val"] = alerts_df["priority"].map(lambda x: priority_order.get(x, 0))
        alerts_df_sorted = alerts_df.sort_values(by=["prio_val", "timestamp"], ascending=[False, False])

        st.subheader("Active & Historical Alerts Table")
        alert_display_cols = [c for c in ["status", "priority", "severity", "rule_id", "resource", "risk_score", "timestamp"] if c in alerts_df_sorted.columns]
        st.dataframe(alerts_df_sorted[alert_display_cols], use_container_width=True)

        st.subheader("Alert Details")
        for _, alert_row in alerts_df_sorted.iterrows():
            status_str = alert_row.get("status", "OPEN")
            status_icon = "🔴 OPEN" if status_str == "OPEN" else "🟢 RESOLVED"
            prio_str = alert_row.get("priority", "UNKNOWN")
            
            with st.expander(f"{status_icon} | [{prio_str.upper()}] {alert_row.get('rule_id')} - {alert_row.get('resource')}"):
                st.write(f"**Alert ID:** `{alert_row.get('alert_id')}` | **Created At:** {alert_row.get('timestamp')}")
                st.write(f"**Status:** {status_str} | **Priority:** {prio_str} | **Severity:** {alert_row.get('severity')} | **Risk Score:** {alert_row.get('risk_score')}")
                st.write(f"**Affected Resource:** `{alert_row.get('resource')}` ({alert_row.get('resource_type')})")
                st.write(f"**Risk Message:** {alert_row.get('message')}")
                st.write(f"**Recommended Action:** {alert_row.get('remediation')}")
    else:
        st.info("No security alerts generated yet.")

    st.sidebar.header("Filter Violations")
    violations = report.get("detailed_violations", [])
    violations_df = pd.DataFrame(violations) if violations else pd.DataFrame()

    if not violations_df.empty:
        frameworks = ["All"] + list(violations_df["framework"].unique()) if "framework" in violations_df.columns else ["All"]
        severities = ["All"] + list(violations_df["severity"].unique()) if "severity" in violations_df.columns else ["All"]
        priorities = ["All"] + list(violations_df["priority"].unique()) if "priority" in violations_df.columns else ["All"]
        statuses = ["All"] + list(violations_df["status"].unique()) if "status" in violations_df.columns else ["All"]
        resource_types = ["All"] + list(violations_df["resource_type"].unique()) if "resource_type" in violations_df.columns else ["All"]

        sel_framework = st.sidebar.selectbox("Framework", frameworks)
        sel_severity = st.sidebar.selectbox("Severity", severities)
        sel_priority = st.sidebar.selectbox("Priority", priorities)
        sel_status = st.sidebar.selectbox("Status", statuses)
        sel_res_type = st.sidebar.selectbox("Resource Type", resource_types)

        filtered_df = violations_df.copy()
        if sel_framework != "All" and "framework" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["framework"] == sel_framework]
        if sel_severity != "All" and "severity" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["severity"] == sel_severity]
        if sel_priority != "All" and "priority" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["priority"] == sel_priority]
        if sel_status != "All" and "status" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["status"] == sel_status]
        if sel_res_type != "All" and "resource_type" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["resource_type"] == sel_res_type]
    else:
        filtered_df = violations_df

    st.header("🎯 Security Findings & Remediation")
    rem_summary = report.get("remediation_summary", {})
    rcol1, rcol2, rcol3, rcol4, rcol5 = st.columns(5)
    rcol1.metric("Total Findings", summary["failed_checks"])
    rcol2.metric("Immediate", rem_summary.get("Immediate", 0))
    rcol3.metric("High", rem_summary.get("High", 0))
    rcol4.metric("Medium", rem_summary.get("Medium", 0))
    rcol5.metric("Low", rem_summary.get("Low", 0))

    if not violations_df.empty:
        failed_df = filtered_df[filtered_df["status"] == "FAIL"] if "status" in filtered_df.columns else filtered_df
        if not failed_df.empty:
            priority_order = {"Immediate": 4, "High": 3, "Medium": 2, "Low": 1, "Unassigned": 0}
            failed_df_sorted = failed_df.copy()
            failed_df_sorted["prio_val"] = failed_df_sorted["priority"].map(lambda x: priority_order.get(x, 0))
            failed_df_sorted = failed_df_sorted.sort_values(by=["prio_val", "risk_score"], ascending=[False, False])

            st.subheader("Prioritized Security Findings")
            rem_display_cols = [c for c in ["priority", "risk_score", "rule_id", "resource", "severity", "risk_description", "remediation"] if c in failed_df_sorted.columns]
            st.dataframe(failed_df_sorted[rem_display_cols], use_container_width=True)

            st.subheader("Remediation Details")
            for _, row in failed_df_sorted.iterrows():
                prio_str = str(row.get("priority", "UNASSIGNED"))
                prio_icon = "🔴" if prio_str in ["Immediate", "High"] else ("🟡" if prio_str == "Medium" else "🟢")
                with st.expander(f"{prio_icon} [{prio_str.upper()}] {row.get('rule_id')} - {row.get('resource')}"):
                    st.write(f"**Priority:** {prio_str} | **Risk Score:** {row.get('risk_score', 0)} | **Severity:** {row.get('severity')}")
                    st.write(f"**Affected Resource:** `{row.get('resource')}` ({row.get('resource_type')})")
                    st.write(f"**Risk Description:** {row.get('risk_description')}")
                    st.write(f"**Recommended Action:** {row.get('remediation')}")
                    if row.get('control_id') and row.get('control_id') != "Unmapped":
                        st.write(f"**Framework Control:** {row.get('framework')} {row.get('control_id')} - {row.get('control_title')}")

    st.header("Violations by Severity")
    severity_data = report.get("severity_breakdown", {})
    if severity_data:
        severity_df = pd.DataFrame(
            list(severity_data.items()),
            columns=["Severity", "Count"]
        )
        st.bar_chart(severity_df.set_index("Severity"))
    else:
        st.info("No violations found.")

    st.header("Violations by Resource Type")
    resource_data = report.get("resource_type_breakdown", {})
    if resource_data:
        resource_df = pd.DataFrame(
            list(resource_data.items()),
            columns=["Resource Type", "Count"]
        )
        st.bar_chart(resource_df.set_index("Resource Type"))
    else:
        st.info("No violations by resource type.")

    st.header("Detailed Violations")
    if not filtered_df.empty:
        display_cols = [c for c in ["resource", "resource_type", "rule_id", "control_id", "control_title", "severity", "priority", "status", "message"] if c in filtered_df.columns]
        st.dataframe(
            filtered_df[display_cols],
            use_container_width=True
        )
    else:
        st.success("No violations detected!")


if __name__ == "__main__":
    main()
