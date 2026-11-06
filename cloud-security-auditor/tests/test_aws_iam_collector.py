"""Unit tests for AWS IAM collector."""

from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from src.aws_collector import AWSCloudCollector, AWSIAMCollector, HAS_BOTO3
from src.models import IAMUser
from src.rules import check_privileged_user_mfa


@pytest.mark.skipif(not HAS_BOTO3, reason="boto3 is not installed")
class TestAWSIAMCollector:
    """Test suite for AWSIAMCollector logic."""

    @patch("boto3.Session")
    def test_collect_iam_users_basic(self, mock_session):
        """Verify IAM users are correctly collected."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [
                {
                    "UserName": "admin_user",
                    "Arn": "arn:aws:iam::123456789012:user/admin_user",
                    "UserId": "AIDAEXAMPLE123",
                    "CreateDate": "2026-01-01T00:00:00Z"
                }
            ]
        }
        mock_iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin_user"}]
        }
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLE1", "Status": "Active", "CreateDate": "2026-01-01"}
            ]
        }
        mock_iam.list_groups_for_user.return_value = {"Groups": []}
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        }
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}
        mock_iam.get_login_profile.return_value = {"LoginProfile": {"UserName": "admin_user"}}

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert len(users) == 1
        user = users[0]
        assert isinstance(user, IAMUser)
        assert user.username == "admin_user"
        assert user.arn == "arn:aws:iam::123456789012:user/admin_user"
        assert user.mfa_enabled is True
        assert user.privileged is True
        assert user.console_access is True
        assert len(user.access_keys) == 1
        assert user.access_keys[0]["AccessKeyId"] == "AKIAEXAMPLE1"
        assert "SecretAccessKey" not in user.access_keys[0]

    @patch("boto3.Session")
    def test_privileged_user_with_mfa_passes(self, mock_session):
        """Verify privileged user with MFA passes IAM-MFA-001."""
        user = IAMUser(username="admin1", role="admin", mfa_enabled=True, privileged=True)
        res = check_privileged_user_mfa(user)
        assert res.status == "PASS"
        assert res.rule_id == "IAM-MFA-001"

    @patch("boto3.Session")
    def test_privileged_user_without_mfa_fails(self, mock_session):
        """Verify privileged user without MFA fails IAM-MFA-001 with HIGH severity."""
        user = IAMUser(username="admin2", role="admin", mfa_enabled=False, privileged=True)
        res = check_privileged_user_mfa(user)
        assert res.status == "FAIL"
        assert res.severity == "HIGH"
        assert res.rule_id == "IAM-MFA-001"

    @patch("boto3.Session")
    def test_non_privileged_user_without_mfa_no_violation(self, mock_session):
        """Verify non-privileged user without MFA does not fail IAM-MFA-001."""
        user = IAMUser(username="dev1", role="user", mfa_enabled=False, privileged=False)
        res = check_privileged_user_mfa(user)
        assert res.status == "PASS"

    @patch("boto3.Session")
    def test_administrator_access_policy_recognized_as_privileged(self, mock_session):
        """Verify attached AdministratorAccess policy causes user to be marked privileged."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "policy_user", "Arn": "arn:aws:iam::123:user/policy_user"}]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_iam.list_groups_for_user.return_value = {"Groups": []}
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        }
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}
        mock_iam.get_login_profile.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert len(users) == 1
        assert users[0].privileged is True

    @patch("boto3.Session")
    def test_group_privilege_inheritance(self, mock_session):
        """Verify privilege inherited through an IAM group."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "group_user", "Arn": "arn:aws:iam::123:user/group_user"}]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_iam.list_groups_for_user.return_value = {
            "Groups": [{"GroupName": "Admins"}]
        }
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}
        mock_iam.get_login_profile.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert len(users) == 1
        assert users[0].privileged is True
        assert "Admins" in users[0].groups

    @patch("boto3.Session")
    def test_access_keys_metadata_collected_secrets_never_stored(self, mock_session):
        """Verify access key metadata (Active/Inactive) is collected and secret keys are never stored."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "key_user", "Arn": "arn:aws:iam::123:user/key_user"}]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIA1111", "Status": "Active", "CreateDate": "2026-01-01"},
                {"AccessKeyId": "AKIA2222", "Status": "Inactive", "CreateDate": "2025-01-01"}
            ]
        }
        mock_iam.list_groups_for_user.return_value = {"Groups": []}
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}
        mock_iam.get_login_profile.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert len(users) == 1
        keys = users[0].access_keys
        assert len(keys) == 2
        assert keys[0]["Status"] == "Active"
        assert keys[1]["Status"] == "Inactive"
        for k in keys:
            assert "SecretAccessKey" not in k
            assert "AWSSecretAccessKey" not in k
            assert "Secret" not in k

    @patch("boto3.Session")
    def test_console_access_detection(self, mock_session):
        """Verify console-login information is handled correctly."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam

        mock_iam.list_users.return_value = {
            "Users": [
                {"UserName": "console_user"},
                {"UserName": "cli_only_user"}
            ]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_iam.list_groups_for_user.return_value = {"Groups": []}
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_user_policies.return_value = {"PolicyNames": []}

        def get_login_profile_side_effect(UserName):
            if UserName == "console_user":
                return {"LoginProfile": {"UserName": "console_user"}}
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetLoginProfile")

        mock_iam.get_login_profile.side_effect = get_login_profile_side_effect

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert len(users) == 2
        u_map = {u.username: u for u in users}
        assert u_map["console_user"].console_access is True
        assert u_map["cli_only_user"].console_access is False

    @patch("boto3.Session")
    def test_empty_iam_users_response(self, mock_session):
        """Verify empty IAM responses are handled gracefully."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        mock_iam.list_users.return_value = {"Users": []}

        collector = AWSCloudCollector()
        users = collector.collect_iam()

        assert users == []

    @patch("boto3.Session")
    def test_iam_missing_credentials(self, mock_session):
        """Verify NoCredentialsError raises ConnectionError."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        mock_iam.list_users.side_effect = NoCredentialsError()

        collector = AWSCloudCollector()
        with pytest.raises(ConnectionError, match="AWS credentials were not found"):
            collector.collect_iam()

    @patch("boto3.Session")
    def test_iam_access_denied(self, mock_session):
        """Verify ClientError AccessDenied raises ConnectionError."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        mock_iam.list_users.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}}, "ListUsers"
        )

        collector = AWSCloudCollector()
        with pytest.raises(ConnectionError, match="Access denied to AWS IAM"):
            collector.collect_iam()

    @patch("boto3.Session")
    def test_iam_generic_api_failure(self, mock_session):
        """Verify generic ClientError raises ConnectionError."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        mock_iam.list_users.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}}, "ListUsers"
        )

        collector = AWSCloudCollector()
        with pytest.raises(ConnectionError, match="AWS API error"):
            collector.collect_iam()

    def test_aws_iam_collector_alias(self):
        """Verify AWSIAMCollector class alias exists."""
        assert issubclass(AWSIAMCollector, AWSCloudCollector)
