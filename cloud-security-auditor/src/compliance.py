"""Compliance framework mapping module for cloud security rules."""

from typing import List, Dict, Any

COMPLIANCE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "STORAGE-PUBLIC-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "2.1.5",
        "control_title": "Ensure S3 Bucket Public Access Block is enabled",
        "compliance_category": "Storage Security",
        "description": "Storage buckets must block public read/write permissions to prevent unauthorized data exposure."
    },
    "IAM-MFA-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "1.5",
        "control_title": "Ensure MFA is enabled for all IAM users with privileged access",
        "compliance_category": "Identity & Access Management",
        "description": "Privileged IAM accounts (administrative/power roles) must enforce Multi-Factor Authentication."
    },
    "ENCRYPTION-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "2.2.1",
        "control_title": "Ensure cloud data storage and volumes are encrypted at rest",
        "compliance_category": "Data Protection",
        "description": "All storage buckets, virtual machine volumes, and database storage must have server-side encryption enabled."
    },
    "NETWORK-PORT-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "5.1",
        "control_title": "Ensure no security groups allow unrestricted ingress to risky management ports",
        "compliance_category": "Network Security",
        "description": "Security groups must not expose administration ports (e.g., SSH 22, RDP 3389) or database ports directly to 0.0.0.0/0."
    },
    "DATABASE-PUBLIC-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "2.3.1",
        "control_title": "Ensure RDS Database instances are not publicly accessible",
        "compliance_category": "Database Security",
        "description": "Database instances containing production or internal data must be provisioned in private subnets without public IPs."
    },
    "DATABASE-BACKUP-001": {
        "framework": "CIS AWS Foundations Benchmark",
        "control_id": "2.3.2",
        "control_title": "Ensure automated backups are enabled for RDS database instances",
        "compliance_category": "Resilience & Backup",
        "description": "Relational database services should have automated backup retention policies enabled for disaster recovery."
    }
}


def get_rule_compliance_mapping(rule_id: str) -> Dict[str, str]:
    """Retrieve compliance framework mapping for a rule ID.

    Returns fallback dictionary if the rule ID is not mapped.
    """
    return COMPLIANCE_MAPPINGS.get(rule_id, {
        "framework": "Unmapped",
        "control_id": "Unmapped",
        "control_title": "Unmapped Control",
        "compliance_category": "General",
        "description": "Framework mapping: pending verification"
    })


def enrich_compliance_result(result: Any) -> Any:
    """Attach framework mapping fields to a ComplianceResult object."""
    rule_id = getattr(result, "rule_id", "UNKNOWN")
    mapping = get_rule_compliance_mapping(rule_id)

    setattr(result, "framework", mapping["framework"])
    setattr(result, "control_id", mapping["control_id"])
    setattr(result, "control_title", mapping["control_title"])
    setattr(result, "compliance_category", mapping["compliance_category"])

    return result


def calculate_framework_summary(results: List[Any], framework_name: str = "CIS AWS Foundations Benchmark") -> Dict[str, Any]:
    """Calculate framework-level statistics from compliance check results."""
    framework_results = [
        r for r in results
        if getattr(r, 'framework', 'Unmapped') != 'Unmapped'
    ]
    if not framework_results:
        return {
            "framework": framework_name,
            "controls_evaluated": 0,
            "controls_passed": 0,
            "controls_failed": 0,
            "coverage_percentage": 0.0,
            "control_status": {}
        }

    control_checks: Dict[str, Dict[str, Any]] = {}
    for r in framework_results:
        cid = getattr(r, 'control_id', 'Unmapped')
        if cid not in control_checks:
            control_checks[cid] = {
                "control_id": cid,
                "control_title": getattr(r, 'control_title', ''),
                "category": getattr(r, 'compliance_category', 'General'),
                "results": []
            }
        control_checks[cid]["results"].append(r)

    controls_evaluated = len(control_checks)
    controls_passed = 0
    controls_failed = 0
    control_status: Dict[str, Dict[str, Any]] = {}

    for cid, info in control_checks.items():
        fails = [r for r in info["results"] if getattr(r, 'status', '') == 'FAIL']
        if fails:
            controls_failed += 1
            status = "FAIL"
        else:
            controls_passed += 1
            status = "PASS"
        control_status[cid] = {
            "control_id": cid,
            "control_title": info["control_title"],
            "category": info["category"],
            "status": status,
            "total_checks": len(info["results"]),
            "failed_checks": len(fails)
        }

    coverage = (controls_passed / controls_evaluated * 100) if controls_evaluated > 0 else 0.0

    return {
        "framework": framework_name,
        "controls_evaluated": controls_evaluated,
        "controls_passed": controls_passed,
        "controls_failed": controls_failed,
        "coverage_percentage": round(coverage, 2),
        "control_status": control_status
    }
