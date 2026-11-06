"""Security compliance rules for cloud resources."""

from dataclasses import dataclass
from typing import List

from src.models import StorageBucket, VirtualMachine, Database, IAMUser
from config import PRIVILEGED_ROLES, ALLOWED_PORTS, RISKY_PORTS, RULE_SEVERITY


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    rule_id: str
    resource: str
    resource_type: str
    status: str
    severity: str
    message: str
    framework: str = "CIS AWS Foundations Benchmark"
    control_id: str = "Unmapped"
    control_title: str = ""
    compliance_category: str = "General"
    risk_description: str = ""
    remediation: str = ""
    priority: str = "Unassigned"
    risk_score: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "framework": self.framework,
            "control_id": self.control_id,
            "control_title": self.control_title,
            "compliance_category": self.compliance_category,
            "risk_description": self.risk_description,
            "remediation": self.remediation,
            "priority": self.priority,
            "risk_score": self.risk_score
        }


def check_storage_public_access(resource: StorageBucket) -> ComplianceResult:
    """Check if storage bucket has public access enabled.

    Evaluates PublicAccessBlock, Bucket Policy, and Bucket ACL.
    """
    pab = getattr(resource, 'public_access_block', None) or {}
    public_policy = getattr(resource, 'public_policy', False)
    public_acl = getattr(resource, 'public_acl', False)

    block_policy = pab.get("BlockPublicPolicy", False) if isinstance(pab, dict) else False
    restrict_policy = pab.get("RestrictPublicBuckets", False) if isinstance(pab, dict) else False
    ignore_acls = pab.get("IgnorePublicAcls", False) if isinstance(pab, dict) else False

    policy_is_public = public_policy and not (block_policy and restrict_policy)
    acl_is_public = public_acl and not ignore_acls

    if policy_is_public:
        return ComplianceResult(
            rule_id="STORAGE-PUBLIC-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="FAIL",
            severity=RULE_SEVERITY.get("STORAGE-PUBLIC-001", "HIGH"),
            message=f"Storage bucket '{resource.name}' is publicly accessible (Bucket policy permits public access)."
        )

    if acl_is_public:
        return ComplianceResult(
            rule_id="STORAGE-PUBLIC-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="FAIL",
            severity=RULE_SEVERITY.get("STORAGE-PUBLIC-001", "HIGH"),
            message=f"Storage bucket '{resource.name}' is publicly accessible (Bucket ACL permits public access)."
        )

    if resource.public_access:
        return ComplianceResult(
            rule_id="STORAGE-PUBLIC-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="FAIL",
            severity=RULE_SEVERITY.get("STORAGE-PUBLIC-001", "HIGH"),
            message=f"Storage bucket '{resource.name}' is publicly accessible."
        )

    return ComplianceResult(
        rule_id="STORAGE-PUBLIC-001",
        resource=resource.name,
        resource_type=resource.resource_type,
        status="PASS",
        severity=RULE_SEVERITY.get("STORAGE-PUBLIC-001", "HIGH"),
        message=f"Storage bucket '{resource.name}' is not publicly accessible."
    )


def check_privileged_user_mfa(resource: IAMUser) -> ComplianceResult:
    """Check if privileged user has MFA enabled."""
    is_privileged = getattr(resource, 'privileged', None)
    if is_privileged is None:
        is_privileged = resource.role.lower() in [role.lower() for role in PRIVILEGED_ROLES]
    else:
        is_privileged = bool(is_privileged) or (resource.role.lower() in [role.lower() for role in PRIVILEGED_ROLES])

    username = getattr(resource, 'username', getattr(resource, 'name', 'unknown'))
    mfa_enabled = getattr(resource, 'mfa_enabled', False)
    if not mfa_enabled and getattr(resource, 'mfa_devices', None):
        mfa_enabled = len(resource.mfa_devices) > 0

    if is_privileged:
        if not mfa_enabled:
            return ComplianceResult(
                rule_id="IAM-MFA-001",
                resource=username,
                resource_type=resource.resource_type,
                status="FAIL",
                severity=RULE_SEVERITY.get("IAM-MFA-001", "HIGH"),
                message=f"Privileged user '{username}' (role: {resource.role}) does not have MFA enabled."
            )
        return ComplianceResult(
            rule_id="IAM-MFA-001",
            resource=username,
            resource_type=resource.resource_type,
            status="PASS",
            severity=RULE_SEVERITY.get("IAM-MFA-001", "HIGH"),
            message=f"Privileged user '{username}' (role: {resource.role}) has MFA enabled."
        )
    return ComplianceResult(
        rule_id="IAM-MFA-001",
        resource=username,
        resource_type=resource.resource_type,
        status="PASS",
        severity=RULE_SEVERITY.get("IAM-MFA-001", "HIGH"),
        message=f"User '{username}' (role: {resource.role}) is not a privileged user."
    )


def check_encryption(resource) -> ComplianceResult:
    """Check if resource has encryption enabled."""
    resource_name = getattr(resource, 'name', getattr(resource, 'username', 'unknown'))
    resource_type = getattr(resource, 'resource_type', 'unknown')

    if not resource.encrypted:
        return ComplianceResult(
            rule_id="ENCRYPTION-001",
            resource=resource_name,
            resource_type=resource_type,
            status="FAIL",
            severity=RULE_SEVERITY.get("ENCRYPTION-001", "HIGH"),
            message=f"Resource '{resource_name}' is not encrypted."
        )
    return ComplianceResult(
        rule_id="ENCRYPTION-001",
        resource=resource_name,
        resource_type=resource_type,
        status="PASS",
        severity=RULE_SEVERITY.get("ENCRYPTION-001", "HIGH"),
        message=f"Resource '{resource_name}' is encrypted."
    )


def check_open_ports(resource: VirtualMachine) -> List[ComplianceResult]:
    """Check if VM has unnecessary open ports exposed publicly."""
    results = []

    if not resource.public_ip:
        results.append(ComplianceResult(
            rule_id="NETWORK-PORT-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="PASS",
            severity=RULE_SEVERITY.get("NETWORK-PORT-001", "MEDIUM"),
            message=f"VM '{resource.name}' does not have a public IP."
        ))
        return results

    risky_ports_found = [
        port for port in resource.open_ports if port in RISKY_PORTS
    ]

    if risky_ports_found:
        ports_str = ", ".join(str(p) for p in risky_ports_found)
        severity = "HIGH" if (22 in risky_ports_found or 3389 in risky_ports_found) else RULE_SEVERITY.get("NETWORK-PORT-001", "MEDIUM")
        results.append(ComplianceResult(
            rule_id="NETWORK-PORT-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="FAIL",
            severity=severity,
            message=f"VM '{resource.name}' has risky ports publicly exposed: {ports_str}."
        ))
    else:
        results.append(ComplianceResult(
            rule_id="NETWORK-PORT-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="PASS",
            severity=RULE_SEVERITY.get("NETWORK-PORT-001", "MEDIUM"),
            message=f"VM '{resource.name}' has no risky ports publicly exposed."
        ))

    return results


def check_database_public_access(resource: Database) -> ComplianceResult:
    """Check if database has public access enabled."""
    if resource.public_access:
        return ComplianceResult(
            rule_id="DATABASE-PUBLIC-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="FAIL",
            severity=RULE_SEVERITY.get("DATABASE-PUBLIC-001", "HIGH"),
            message=f"RDS database '{resource.name}' is publicly accessible."
        )
    return ComplianceResult(
        rule_id="DATABASE-PUBLIC-001",
        resource=resource.name,
        resource_type=resource.resource_type,
        status="PASS",
        severity=RULE_SEVERITY.get("DATABASE-PUBLIC-001", "HIGH"),
        message=f"RDS database '{resource.name}' is not publicly accessible."
    )


def check_database_backup(resource: Database) -> ComplianceResult:
    """Check if database has automated backups configured."""
    retention = getattr(resource, 'backup_retention_period', None)
    if retention is not None and retention > 0:
        return ComplianceResult(
            rule_id="DATABASE-BACKUP-001",
            resource=resource.name,
            resource_type=resource.resource_type,
            status="PASS",
            severity=RULE_SEVERITY.get("DATABASE-BACKUP-001", "MEDIUM"),
            message=f"RDS database '{resource.name}' has automated backups configured (retention: {retention} days)."
        )
    return ComplianceResult(
        rule_id="DATABASE-BACKUP-001",
        resource=resource.name,
        resource_type=resource.resource_type,
        status="FAIL",
        severity=RULE_SEVERITY.get("DATABASE-BACKUP-001", "MEDIUM"),
        message=f"RDS database '{resource.name}' does not have automated backups configured."
    )

