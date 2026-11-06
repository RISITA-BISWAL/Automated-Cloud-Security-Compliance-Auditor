"""Unit tests for compliance rules."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import StorageBucket, VirtualMachine, Database, IAMUser
from src.rules import (
    check_storage_public_access,
    check_privileged_user_mfa,
    check_encryption,
    check_open_ports
)


class TestStoragePublicAccess:
    """Tests for storage public access rule."""

    def test_private_bucket_passes(self):
        bucket = StorageBucket(name="private-bucket", public_access=False, encrypted=True)
        result = check_storage_public_access(bucket)
        assert result.status == "PASS"
        assert result.rule_id == "STORAGE-PUBLIC-001"

    def test_public_bucket_fails(self):
        bucket = StorageBucket(name="public-bucket", public_access=True, encrypted=True)
        result = check_storage_public_access(bucket)
        assert result.status == "FAIL"
        assert result.severity == "HIGH"

    def test_result_has_correct_resource_name(self):
        bucket = StorageBucket(name="test-bucket", public_access=False, encrypted=True)
        result = check_storage_public_access(bucket)
        assert result.resource == "test-bucket"
        assert result.resource_type == "storage"

    def test_public_policy_bucket_fails(self):
        bucket = StorageBucket(
            name="public-policy-bucket",
            public_access=True,
            encrypted=True,
            public_policy=True,
            public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
        )
        result = check_storage_public_access(bucket)
        assert result.status == "FAIL"
        assert "Bucket policy permits public access" in result.message

    def test_public_acl_bucket_fails(self):
        bucket = StorageBucket(
            name="public-acl-bucket",
            public_access=True,
            encrypted=True,
            public_acl=True,
            public_access_block={"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        )
        result = check_storage_public_access(bucket)
        assert result.status == "FAIL"
        assert "Bucket ACL permits public access" in result.message

    def test_all_pab_blocked_and_private_policy_passes(self):
        bucket = StorageBucket(
            name="secure-bucket",
            public_access=False,
            encrypted=True,
            public_policy=False,
            public_acl=False,
            public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        )
        result = check_storage_public_access(bucket)
        assert result.status == "PASS"


class TestPrivilegedUserMFA:
    """Tests for privileged user MFA rule."""

    def test_admin_with_mfa_passes(self):
        user = IAMUser(username="alice", role="admin", mfa_enabled=True)
        result = check_privileged_user_mfa(user)
        assert result.status == "PASS"
        assert result.rule_id == "IAM-MFA-001"

    def test_admin_without_mfa_fails(self):
        user = IAMUser(username="charlie", role="admin", mfa_enabled=False)
        result = check_privileged_user_mfa(user)
        assert result.status == "FAIL"
        assert result.severity == "HIGH"

    def test_security_admin_with_mfa_passes(self):
        user = IAMUser(username="diana", role="security_admin", mfa_enabled=True)
        result = check_privileged_user_mfa(user)
        assert result.status == "PASS"

    def test_security_admin_without_mfa_fails(self):
        user = IAMUser(username="diana", role="security_admin", mfa_enabled=False)
        result = check_privileged_user_mfa(user)
        assert result.status == "FAIL"

    def test_non_privileged_user_passes(self):
        user = IAMUser(username="bob", role="developer", mfa_enabled=False)
        result = check_privileged_user_mfa(user)
        assert result.status == "PASS"

    def test_analyst_user_passes(self):
        user = IAMUser(username="eve", role="analyst", mfa_enabled=True)
        result = check_privileged_user_mfa(user)
        assert result.status == "PASS"


class TestEncryption:
    """Tests for encryption rule."""

    def test_encrypted_storage_passes(self):
        bucket = StorageBucket(name="encrypted-bucket", public_access=False, encrypted=True)
        result = check_encryption(bucket)
        assert result.status == "PASS"
        assert result.rule_id == "ENCRYPTION-001"

    def test_unencrypted_storage_fails(self):
        bucket = StorageBucket(name="unencrypted-bucket", public_access=False, encrypted=False)
        result = check_encryption(bucket)
        assert result.status == "FAIL"
        assert result.severity == "HIGH"

    def test_encrypted_vm_passes(self):
        vm = VirtualMachine(name="encrypted-vm", encrypted=True, public_ip=False)
        result = check_encryption(vm)
        assert result.status == "PASS"

    def test_unencrypted_vm_fails(self):
        vm = VirtualMachine(name="unencrypted-vm", encrypted=False, public_ip=False)
        result = check_encryption(vm)
        assert result.status == "FAIL"

    def test_encrypted_database_passes(self):
        db = Database(name="encrypted-db", encrypted=True, public_access=False)
        result = check_encryption(db)
        assert result.status == "PASS"

    def test_unencrypted_database_fails(self):
        db = Database(name="unencrypted-db", encrypted=False, public_access=False)
        result = check_encryption(db)
        assert result.status == "FAIL"


class TestOpenPorts:
    """Tests for open ports rule."""

    def test_vm_without_public_ip_passes(self):
        vm = VirtualMachine(name="private-vm", encrypted=True, public_ip=False, open_ports=[22])
        results = check_open_ports(vm)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_vm_with_allowed_ports_passes(self):
        vm = VirtualMachine(name="web-server", encrypted=True, public_ip=True, open_ports=[80, 443])
        results = check_open_ports(vm)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_vm_with_risky_ports_fails(self):
        vm = VirtualMachine(name="exposed-vm", encrypted=True, public_ip=True, open_ports=[22, 3389])
        results = check_open_ports(vm)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].severity == "HIGH"

    def test_vm_with_mixed_ports_fails(self):
        vm = VirtualMachine(name="mixed-vm", encrypted=True, public_ip=True, open_ports=[80, 22])
        results = check_open_ports(vm)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert "22" in results[0].message

    def test_result_has_correct_rule_id(self):
        vm = VirtualMachine(name="test-vm", encrypted=True, public_ip=True, open_ports=[22])
        results = check_open_ports(vm)
        assert results[0].rule_id == "NETWORK-PORT-001"
