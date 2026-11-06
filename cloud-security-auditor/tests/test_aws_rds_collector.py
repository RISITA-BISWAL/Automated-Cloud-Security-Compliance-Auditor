"""Unit tests for the AWS RDS collector and database rules."""

import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import NoCredentialsError, ClientError

from src.aws_collector import AWSCloudCollector, AWSRDSCollector
from src.models import Database
from src.rules import (
    check_database_public_access,
    check_database_backup,
    check_encryption
)
from src.auditor import Auditor


class TestAWSRDSCollector:
    """Tests for AWS RDS collection functionality."""

    @patch("boto3.Session")
    def test_collect_rds_instances_basic(self, mock_session):
        """Test basic collection of RDS instances."""
        mock_client = MagicMock()
        mock_client.meta.region_name = "us-east-1"
        mock_session.return_value.client.return_value = mock_client
        mock_session.return_value.region_name = "us-east-1"

        mock_client.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-db",
                    "Engine": "postgres",
                    "EngineVersion": "14.5",
                    "DBInstanceStatus": "available",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/test",
                    "BackupRetentionPeriod": 7,
                    "MultiAZ": True,
                    "VpcSecurityGroups": [
                        {"VpcSecurityGroupId": "sg-123456", "Status": "active"}
                    ]
                }
            ]
        }

        collector = AWSCloudCollector(region="us-east-1")
        dbs = collector.collect_rds()

        assert len(dbs) == 1
        db = dbs[0]
        assert isinstance(db, Database)
        assert db.name == "prod-db"
        assert db.engine == "postgres"
        assert db.engine_version == "14.5"
        assert db.status == "available"
        assert db.public_access is False
        assert db.encrypted is True
        assert db.kms_key_id == "arn:aws:kms:us-east-1:123456789012:key/test"
        assert db.backup_retention_period == 7
        assert db.multi_az is True
        assert len(db.vpc_security_groups) == 1

    @patch("boto3.Session")
    def test_publicly_accessible_pass_and_fail(self, mock_session):
        """Test public accessibility rule evaluation."""
        private_db = Database(name="private-db", encrypted=True, public_access=False)
        public_db = Database(name="public-db", encrypted=True, public_access=True)

        res_private = check_database_public_access(private_db)
        assert res_private.status == "PASS"
        assert res_private.severity == "HIGH"
        assert "not publicly accessible" in res_private.message

        res_public = check_database_public_access(public_db)
        assert res_public.status == "FAIL"
        assert res_public.severity == "HIGH"
        assert "publicly accessible" in res_public.message

    @patch("boto3.Session")
    def test_rds_encryption_pass_and_fail(self, mock_session):
        """Test storage encryption rule evaluation."""
        encrypted_db = Database(name="enc-db", encrypted=True, public_access=False)
        unencrypted_db = Database(name="unenc-db", encrypted=False, public_access=False)

        res_enc = check_encryption(encrypted_db)
        assert res_enc.status == "PASS"

        res_unenc = check_encryption(unencrypted_db)
        assert res_unenc.status == "FAIL"

    @patch("boto3.Session")
    def test_backup_retention_period(self, mock_session):
        """Test backup retention period rule evaluation."""
        db_with_backup = Database(name="db-backup", encrypted=True, public_access=False, backup_retention_period=7)
        db_no_backup = Database(name="db-no-backup", encrypted=True, public_access=False, backup_retention_period=0)

        res_pass = check_database_backup(db_with_backup)
        assert res_pass.status == "PASS"
        assert res_pass.severity == "MEDIUM"

        res_fail = check_database_backup(db_no_backup)
        assert res_fail.status == "FAIL"
        assert res_fail.severity == "MEDIUM"

    @patch("boto3.Session")
    def test_multi_az_does_not_cause_violation(self, mock_session):
        """Verify MultiAZ=False does not automatically cause a compliance failure."""
        single_az_db = Database(name="single-az-db", encrypted=True, public_access=False, multi_az=False)
        auditor = Auditor([single_az_db])
        results = auditor.run_all_checks()

        # MultiAZ=False should not create a FAIL result
        violations = [r for r in results if r.status == "FAIL"]
        assert len(violations) == 0
        assert single_az_db.multi_az is False

    @patch("boto3.Session")
    def test_empty_rds_response(self, mock_session):
        """Test handling of empty RDS response."""
        mock_client = MagicMock()
        mock_client.meta.region_name = "us-east-1"
        mock_session.return_value.client.return_value = mock_client

        mock_client.describe_db_instances.return_value = {"DBInstances": []}

        collector = AWSCloudCollector(region="us-east-1")
        dbs = collector.collect_rds()
        assert dbs == []

    @patch("boto3.Session")
    def test_rds_missing_credentials(self, mock_session):
        """Test handling when AWS credentials are missing."""
        mock_client = MagicMock()
        mock_client.describe_db_instances.side_effect = NoCredentialsError()
        mock_session.return_value.client.return_value = mock_client

        collector = AWSCloudCollector(region="us-east-1")
        with pytest.raises(ConnectionError) as exc_info:
            collector.collect_rds()
        assert "credentials were not found" in str(exc_info.value)

    @patch("boto3.Session")
    def test_rds_access_denied(self, mock_session):
        """Test handling of AWS AccessDenied error."""
        mock_client = MagicMock()
        error_response = {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}}
        mock_client.describe_db_instances.side_effect = ClientError(error_response, "DescribeDBInstances")
        mock_session.return_value.client.return_value = mock_client

        collector = AWSCloudCollector(region="us-east-1")
        with pytest.raises(ConnectionError) as exc_info:
            collector.collect_rds()
        assert "Access denied to AWS RDS" in str(exc_info.value)

    @patch("boto3.Session")
    def test_rds_generic_api_failure(self, mock_session):
        """Test handling of generic RDS API error."""
        mock_client = MagicMock()
        error_response = {"Error": {"Code": "InternalError", "Message": "Service error"}}
        mock_client.describe_db_instances.side_effect = ClientError(error_response, "DescribeDBInstances")
        mock_session.return_value.client.return_value = mock_client

        collector = AWSCloudCollector(region="us-east-1")
        with pytest.raises(ConnectionError) as exc_info:
            collector.collect_rds()
        assert "AWS API error" in str(exc_info.value)

    @patch("boto3.Session")
    def test_aws_rds_collector_alias(self, mock_session):
        """Verify AWSRDSCollector alias instantiation."""
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client

        collector = AWSRDSCollector(region="us-east-1")
        assert isinstance(collector, AWSCloudCollector)
