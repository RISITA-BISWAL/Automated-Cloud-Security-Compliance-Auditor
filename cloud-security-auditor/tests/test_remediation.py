"""Unit tests for security risk prioritization and remediation guidance module."""

import pytest
from src.rules import ComplianceResult
from src.remediation import (
    get_remediation_guidance,
    enrich_result,
    enrich_results,
    get_prioritized_findings,
    REMEDIATION_GUIDANCE
)


class TestRemediationModule:
    """Test suite for remediation knowledge base, risk scoring, priority assignment, and findings sorting."""

    def test_guidance_exists_for_storage_public_access(self):
        """1. Verify guidance exists for STORAGE-PUBLIC-001."""
        guidance = get_remediation_guidance("STORAGE-PUBLIC-001", severity="HIGH", status="FAIL")
        assert "storage" in guidance["risk_description"].lower() or "public" in guidance["risk_description"].lower()
        assert guidance["priority"] == "Immediate"
        assert guidance["risk_score"] == 8

    def test_guidance_exists_for_iam_mfa(self):
        """2. Verify guidance exists for IAM-MFA-001."""
        guidance = get_remediation_guidance("IAM-MFA-001", severity="HIGH", status="FAIL")
        assert "mfa" in guidance["risk_description"].lower() or "privileged" in guidance["risk_description"].lower()
        assert guidance["priority"] == "Immediate"
        assert guidance["risk_score"] == 8

    def test_guidance_exists_for_encryption(self):
        """3. Verify guidance exists for ENCRYPTION-001."""
        guidance = get_remediation_guidance("ENCRYPTION-001", severity="HIGH", status="FAIL")
        assert "encrypted" in guidance["risk_description"].lower() or "kms" in guidance["remediation"].lower()
        assert guidance["priority"] == "High"
        assert guidance["risk_score"] == 8

    def test_guidance_exists_for_network_port(self):
        """4. Verify guidance exists for NETWORK-PORT-001."""
        guidance_high = get_remediation_guidance("NETWORK-PORT-001", severity="HIGH", status="FAIL")
        assert "port" in guidance_high["risk_description"].lower() or "ssh" in guidance_high["risk_description"].lower()
        assert guidance_high["priority"] == "Immediate"
        assert guidance_high["risk_score"] == 8

    def test_guidance_exists_for_database_public_access(self):
        """5. Verify guidance exists for DATABASE-PUBLIC-001."""
        guidance = get_remediation_guidance("DATABASE-PUBLIC-001", severity="HIGH", status="FAIL")
        assert "database" in guidance["risk_description"].lower() or "publiclyaccessible" in guidance["remediation"].lower()
        assert guidance["priority"] == "Immediate"
        assert guidance["risk_score"] == 8

    def test_guidance_exists_for_database_backup(self):
        """6. Verify guidance exists for DATABASE-BACKUP-001."""
        guidance = get_remediation_guidance("DATABASE-BACKUP-001", severity="MEDIUM", status="FAIL")
        assert "backup" in guidance["risk_description"].lower() or "retention" in guidance["remediation"].lower()
        assert guidance["priority"] == "Medium"
        assert guidance["risk_score"] == 5

    def test_high_severity_priority_assignment(self):
        """7. Verify HIGH severity rules are assigned Immediate or High priority."""
        guidance = get_remediation_guidance("IAM-MFA-001", severity="HIGH", status="FAIL")
        assert guidance["priority"] in ["Immediate", "High"]

    def test_medium_severity_priority_assignment(self):
        """8. Verify MEDIUM severity rules are assigned Medium priority."""
        guidance = get_remediation_guidance("DATABASE-BACKUP-001", severity="MEDIUM", status="FAIL")
        assert guidance["priority"] == "Medium"

    def test_unknown_rule_fallback(self):
        """9. Verify unknown rules return safe default fallback guidance without crashing."""
        guidance = get_remediation_guidance("UNKNOWN-RULE-999", severity="HIGH", status="FAIL")
        assert guidance["priority"] == "Unassigned"
        assert guidance["risk_score"] == 0
        assert "no remediation guidance" in guidance["risk_description"].lower()

    def test_risk_score_calculation(self):
        """10. Verify internal risk score assignments."""
        guidance_high = get_remediation_guidance("STORAGE-PUBLIC-001", severity="HIGH", status="FAIL")
        guidance_med = get_remediation_guidance("DATABASE-BACKUP-001", severity="MEDIUM", status="FAIL")
        assert guidance_high["risk_score"] == 8
        assert guidance_med["risk_score"] == 5

    def test_findings_sorting(self):
        """11. Verify findings sorting logic."""
        r1 = ComplianceResult(rule_id="DATABASE-BACKUP-001", resource="db1", resource_type="database", status="FAIL", severity="MEDIUM", message="")
        r2 = ComplianceResult(rule_id="IAM-MFA-001", resource="user1", resource_type="iam", status="FAIL", severity="HIGH", message="")

        r1 = enrich_result(r1)
        r2 = enrich_result(r2)

        sorted_findings = get_prioritized_findings([r1, r2])
        assert len(sorted_findings) == 2
        assert sorted_findings[0].rule_id == "IAM-MFA-001"
        assert sorted_findings[1].rule_id == "DATABASE-BACKUP-001"

    def test_immediate_findings_appear_before_medium(self):
        """12. Verify Immediate priority findings appear before Medium priority findings."""
        r_med = ComplianceResult(rule_id="DATABASE-BACKUP-001", resource="db1", resource_type="database", status="FAIL", severity="MEDIUM", message="")
        r_imm = ComplianceResult(rule_id="STORAGE-PUBLIC-001", resource="bucket1", resource_type="storage", status="FAIL", severity="HIGH", message="")

        r_med = enrich_result(r_med)
        r_imm = enrich_result(r_imm)

        sorted_findings = get_prioritized_findings([r_med, r_imm])
        assert sorted_findings[0].priority == "Immediate"
        assert sorted_findings[1].priority == "Medium"

    def test_result_enrichment(self):
        """13. Verify enrich_result attaches all guidance fields to ComplianceResult."""
        res = ComplianceResult(rule_id="STORAGE-PUBLIC-001", resource="bucket1", resource_type="storage", status="FAIL", severity="HIGH", message="")
        enriched = enrich_result(res)

        assert enriched.risk_description != ""
        assert enriched.remediation != ""
        assert enriched.priority == "Immediate"
        assert enriched.risk_score == 8

        res_dict = enriched.to_dict()
        assert "risk_description" in res_dict
        assert "remediation" in res_dict
        assert "priority" in res_dict
        assert "risk_score" in res_dict

    def test_pass_result_handling(self):
        """14. Verify PASS results receive clean non-risk guidance."""
        res = ComplianceResult(rule_id="STORAGE-PUBLIC-001", resource="bucket1", resource_type="storage", status="PASS", severity="HIGH", message="")
        enriched = enrich_result(res)

        assert enriched.priority == "None"
        assert enriched.risk_score == 0
        assert "No risk identified" in enriched.risk_description
        assert "No remediation required" in enriched.remediation
