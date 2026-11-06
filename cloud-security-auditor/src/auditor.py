"""Auditor module for running compliance checks."""

from typing import List, Dict, Any
from collections import defaultdict

from src.models import StorageBucket, VirtualMachine, Database, IAMUser
from src.rules import (
    ComplianceResult,
    check_storage_public_access,
    check_privileged_user_mfa,
    check_encryption,
    check_open_ports,
    check_database_public_access,
    check_database_backup
)
from src.compliance import enrich_compliance_result, calculate_framework_summary
from src.remediation import enrich_result


class Auditor:
    """Orchestrates compliance checks across all resources."""

    def __init__(self, resources: List[Any]):
        self.resources = resources
        self.results: List[ComplianceResult] = []

    def run_all_checks(self) -> List[ComplianceResult]:
        """Run all applicable compliance checks on resources."""
        self.results = []

        for resource in self.resources:
            if isinstance(resource, StorageBucket):
                self.results.append(check_storage_public_access(resource))
                self.results.append(check_encryption(resource))
            elif isinstance(resource, VirtualMachine):
                self.results.extend(check_open_ports(resource))
                self.results.append(check_encryption(resource))
            elif isinstance(resource, Database):
                self.results.append(check_database_public_access(resource))
                self.results.append(check_encryption(resource))
                if getattr(resource, 'backup_retention_period', None) is not None:
                    self.results.append(check_database_backup(resource))
            elif isinstance(resource, IAMUser):
                self.results.append(check_privileged_user_mfa(resource))

        for r in self.results:
            enrich_compliance_result(r)
            enrich_result(r)

        return self.results

    def get_statistics(self) -> Dict[str, Any]:
        """Calculate compliance statistics."""
        total_checks = len(self.results)
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")

        compliance_score = (passed / total_checks * 100) if total_checks > 0 else 0.0
        compliance_score = round(compliance_score, 2)

        severity_counts = defaultdict(int)
        for r in self.results:
            if r.status == "FAIL":
                severity_counts[r.severity] += 1

        resource_type_counts = defaultdict(int)
        for r in self.results:
            if r.status == "FAIL":
                resource_type_counts[r.resource_type] += 1

        remediation_counts = defaultdict(int)
        for r in self.results:
            if r.status == "FAIL":
                remediation_counts[r.priority] += 1

        remediation_summary = {
            "Immediate": remediation_counts["Immediate"],
            "High": remediation_counts["High"],
            "Medium": remediation_counts["Medium"],
            "Low": remediation_counts["Low"]
        }

        framework_summary = calculate_framework_summary(self.results)

        return {
            "total_resources": len(self.resources),
            "total_checks": total_checks,
            "passed_checks": passed,
            "failed_checks": failed,
            "compliance_score": compliance_score,
            "violations_by_severity": dict(severity_counts),
            "violations_by_resource_type": dict(resource_type_counts),
            "remediation_summary": remediation_summary,
            "framework_summary": framework_summary
        }

    def get_violations(self) -> List[ComplianceResult]:
        """Get all failed compliance checks."""
        return [r for r in self.results if r.status == "FAIL"]
