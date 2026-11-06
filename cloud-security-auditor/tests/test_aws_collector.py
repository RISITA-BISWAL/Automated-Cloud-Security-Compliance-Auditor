"""Unit tests for AWS S3 collector."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.aws_collector import AWSCloudCollector, HAS_BOTO3
from src.models import StorageBucket


# Skip all tests if boto3 is not installed
pytestmark = pytest.mark.skipif(
    not HAS_BOTO3, reason="boto3 not installed"
)


class TestAWSCloudCollectorInit:
    """Tests for AWS collector initialization."""

    @patch("src.aws_collector.boto3")
    def test_init_default_region(self, mock_boto3):
        """Test collector initializes with default region."""
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        collector = AWSCloudCollector()

        mock_boto3.Session.assert_called_once_with()
        assert collector.s3_client is not None

    @patch("src.aws_collector.boto3")
    def test_init_specific_region(self, mock_boto3):
        """Test collector initializes with specific region."""
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        collector = AWSCloudCollector(region="eu-west-1")

        mock_boto3.Session.assert_called_once_with(region_name="eu-west-1")

    def test_import_without_boto3(self):
        """Test error message when boto3 is not installed."""
        import src.aws_collector as aws_mod
        original = aws_mod.HAS_BOTO3
        try:
            aws_mod.HAS_BOTO3 = False
            with pytest.raises(ImportError, match="boto3 is not installed"):
                AWSCloudCollector()
        finally:
            aws_mod.HAS_BOTO3 = original


class TestAWSCloudCollectorStorage:
    """Tests for S3 storage collection."""

    @patch("src.aws_collector.boto3")
    def test_collect_storage_returns_list(self, mock_boto3):
        """Test collect_storage returns a list of StorageBucket."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }
        mock_client.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}},
            "GetPublicAccessBlock"
        )
        mock_client.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption"
        )
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert isinstance(resources, list)
        assert len(resources) == 1
        assert isinstance(resources[0], StorageBucket)

    @patch("src.aws_collector.boto3")
    def test_encrypted_bucket(self, mock_boto3):
        """Test that encrypted bucket is detected."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "encrypted-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].encrypted is True

    @patch("src.aws_collector.boto3")
    def test_unencrypted_bucket(self, mock_boto3):
        """Test that unencrypted bucket is detected."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "unencrypted-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        error_response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
        mock_client.get_bucket_encryption.side_effect = ClientError(
            error_response, "GetBucketEncryption"
        )
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].encrypted is False

    @patch("src.aws_collector.boto3")
    def test_public_bucket(self, mock_boto3):
        """Test that public bucket is detected (no public access block)."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "public-bucket"}]
        }
        error_response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
        mock_client.get_public_access_block.side_effect = ClientError(
            error_response, "GetPublicAccessBlock"
        )
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_access is True

    @patch("src.aws_collector.boto3")
    def test_private_bucket(self, mock_boto3):
        """Test that private bucket is detected (public access blocked)."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "private-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_access is False

    @patch("src.aws_collector.boto3")
    def test_collect_returns_dicts(self, mock_boto3):
        """Test collect() returns raw dictionaries."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        result = collector.collect()

        assert isinstance(result, list)
        assert isinstance(result[0], dict)
        assert result[0]["type"] == "storage"
        assert result[0]["name"] == "test-bucket"

    @patch("src.aws_collector.boto3")
    def test_partial_public_access_block(self, mock_boto3):
        """Test that partial public access block is not treated as fully blocked."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "partial-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False
            }
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_access is True


    @patch("src.aws_collector.boto3")
    def test_bucket_policy_public_principal(self, mock_boto3):
        """Test bucket policy with wildcard principal is detected as public."""
        import json
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "public-policy-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-policy-bucket/*"
                }
            ]
        }
        mock_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy_dict)}
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_policy is True
        assert resources[0].public_access is True

    @patch("src.aws_collector.boto3")
    def test_bucket_policy_private(self, mock_boto3):
        """Test bucket policy with specific principal is private."""
        import json
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "private-policy-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "*"
                }
            ]
        }
        mock_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy_dict)}
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_policy is False

    @patch("src.aws_collector.boto3")
    def test_bucket_acl_public_grant(self, mock_boto3):
        """Test bucket ACL with AllUsers grant is detected as public."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {
            "Buckets": [{"Name": "public-acl-bucket"}]
        }
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        mock_client.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ]
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources[0].public_acl is True
        assert resources[0].public_access is True


class TestAWSCloudCollectorErrors:
    """Tests for AWS collector error handling."""

    @patch("src.aws_collector.boto3")
    def test_missing_credentials(self, mock_boto3):
        """Test clear error when AWS credentials are missing."""
        from botocore.exceptions import NoCredentialsError

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.side_effect = NoCredentialsError()

        collector = AWSCloudCollector()

        with pytest.raises(ConnectionError, match="credentials were not found"):
            collector.collect_storage()

    @patch("src.aws_collector.boto3")
    def test_access_denied(self, mock_boto3):
        """Test clear error when access is denied."""
        from botocore.exceptions import ClientError

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        error_response = {"Error": {"Code": "AccessDenied"}}
        mock_client.list_buckets.side_effect = ClientError(
            error_response, "ListBuckets"
        )

        collector = AWSCloudCollector()

        with pytest.raises(ConnectionError, match="Access denied"):
            collector.collect_storage()

    @patch("src.aws_collector.boto3")
    def test_empty_buckets(self, mock_boto3):
        """Test handling of account with no buckets."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.list_buckets.return_value = {"Buckets": []}
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        resources = collector.collect_storage()

        assert resources == []

