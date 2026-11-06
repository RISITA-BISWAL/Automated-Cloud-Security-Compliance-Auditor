"""Security Risk Prioritization and Remediation Guidance Knowledge Base."""

from typing import Dict, Any, List
from src.rules import ComplianceResult


REMEDIATION_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "STORAGE-PUBLIC-001": {
        "risk_description": "Sensitive data stored in public storage buckets may be accessible to unauthorized internet users.",
        "remediation": "Review PublicAccessBlock configuration, bucket policy, and ACLs to restrict unauthorized public access.",
        "priority": "Immediate",
        "estimated_impact": "High",
        "risk_score": 8
    },
    "IAM-MFA-001": {
        "risk_description": "Privileged accounts without Multi-Factor Authentication (MFA) have increased risk of unauthorized access if credentials are compromised.",
        "remediation": "Enable MFA for the privileged IAM user and verify that MFA enforcement policies are applied.",
        "priority": "Immediate",
        "estimated_impact": "High",
        "risk_score": 8
    },
    "ENCRYPTION-001": {
        "risk_description": "Unencrypted storage or compute volumes increase the risk of sensitive data exposure if underlying physical media or backups are compromised.",
        "remediation": "Enable server-side encryption using AWS KMS or AWS managed keys for data at rest.",
        "priority": "High",
        "estimated_impact": "High",
        "risk_score": 8
    },
    "NETWORK-PORT-001": {
        "HIGH": {
            "risk_description": "Publicly exposed administrative ports (e.g., SSH 22, RDP 3389) significantly increase the attack surface for brute-force attacks and remote exploitation.",
            "remediation": "Restrict security group ingress rules to trusted IP CIDR blocks or connect securely via AWS Systems Manager Session Manager.",
            "priority": "Immediate",
            "estimated_impact": "High",
            "risk_score": 8
        },
        "MEDIUM": {
            "risk_description": "Publicly exposed service ports increase the network attack surface for external scans and potential exploitation.",
            "remediation": "Restrict security group ingress rules to authorized application tier security groups or private IP ranges.",
            "priority": "Medium",
            "estimated_impact": "Medium",
            "risk_score": 5
        }
    },
    "DATABASE-PUBLIC-001": {
        "risk_description": "Publicly accessible database instances are vulnerable to unauthorized network access, brute-force attacks, and direct data extraction.",
        "remediation": "Disable the PubliclyAccessible flag on the RDS instance and place it within private database subnets.",
        "priority": "Immediate",
        "estimated_impact": "High",
        "risk_score": 8
    },
    "DATABASE-BACKUP-001": {
        "risk_description": "Lack of automated database backups increases the risk of permanent data loss and prevents point-in-time recovery during outages or corruption.",
        "remediation": "Configure an automated backup retention period (minimum 7 days recommended) for the RDS instance.",
        "priority": "Medium",
        "estimated_impact": "Medium",
        "risk_score": 5
    }
}

PRIORITY_ORDER: Dict[str, int] = {
    "Immediate": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Unassigned": 0,
    "None": -1
}


def get_remediation_guidance(rule_id: str, severity: str = "HIGH", status: str = "FAIL") -> Dict[str, Any]:
    """Retrieve remediation guidance, priority, and risk score for a given rule_id and status."""
    if status == "PASS":
        return {
            "risk_description": "No risk identified.",
            "remediation": "No remediation required.",
            "priority": "None",
            "estimated_impact": "None",
            "risk_score": 0
        }

    rule_info = REMEDIATION_GUIDANCE.get(rule_id)

    if not rule_info:
        return {
            "risk_description": "No remediation guidance is currently defined for this rule.",
            "remediation": "Review the security finding and determine an appropriate remediation.",
            "priority": "Unassigned",
            "estimated_impact": "Unknown",
            "risk_score": 0
        }

    if rule_id == "NETWORK-PORT-001" and isinstance(rule_info, dict):
        sev_info = rule_info.get(severity, rule_info.get("MEDIUM"))
        return dict(sev_info)

    return dict(rule_info)


def enrich_result(result: ComplianceResult) -> ComplianceResult:
    """Enrich a ComplianceResult instance with risk and remediation guidance."""
    guidance = get_remediation_guidance(
        rule_id=result.rule_id,
        severity=result.severity,
        status=result.status
    )

    result.risk_description = guidance["risk_description"]
    result.remediation = guidance["remediation"]
    result.priority = guidance["priority"]
    result.risk_score = guidance["risk_score"]

    return result


def enrich_results(results: List[ComplianceResult]) -> List[ComplianceResult]:
    """Enrich a list of ComplianceResult instances with remediation metadata."""
    return [enrich_result(r) for r in results]


def get_prioritized_findings(results: List[ComplianceResult]) -> List[ComplianceResult]:
    """Filter failed findings and sort by priority (Immediate > High > Medium > Low) and risk_score."""
    failed_findings = [r for r in results if r.status == "FAIL"]

    def sort_key(r: ComplianceResult):
        priority_val = PRIORITY_ORDER.get(r.priority, 0)
        return (priority_val, r.risk_score, r.severity)

    return sorted(failed_findings, key=sort_key, reverse=True)
