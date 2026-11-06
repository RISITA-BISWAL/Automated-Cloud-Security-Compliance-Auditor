"""Unit tests for AWS EC2 collector."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.aws_collector import AWSCloudCollector, AWSEC2Collector, HAS_BOTO3
from src.models import VirtualMachine
from src.rules import check_open_ports, check_encryption


# Skip all tests if boto3 is not installed
pytestmark = pytest.mark.skipif(
    not HAS_BOTO3, reason="boto3 not installed"
)


class TestAWSEC2Collector:
    """Tests for AWS EC2 collector instance and security group collection."""

    @patch("src.aws_collector.boto3")
    def test_collect_ec2_instances_basic(self, mock_boto3):
        """Test collecting basic EC2 instance information."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "PublicIpAddress": "203.0.113.10",
                            "PrivateIpAddress": "10.0.0.15",
                            "Tags": [{"Key": "Name", "Value": "web-server"}],
                            "SecurityGroups": [{"GroupId": "sg-12345", "GroupName": "web-sg"}],
                            "BlockDeviceMappings": [
                                {"Ebs": {"VolumeId": "vol-0123456"}}
                            ]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-12345",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-0123456", "Encrypted": True}]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()

        assert len(vms) == 1
        vm = vms[0]
        assert isinstance(vm, VirtualMachine)
        assert vm.name == "web-server"
        assert vm.instance_id == "i-0123456789abcdef0"
        assert vm.public_ip is True
        assert vm.public_ip_address == "203.0.113.10"
        assert vm.private_ip_address == "10.0.0.15"
        assert vm.encrypted is True
        assert vm.open_ports == [443]

    @patch("src.aws_collector.boto3")
    def test_instance_without_public_ip(self, mock_boto3):
        """Test instance without public IP is collected correctly."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-private123",
                            "InstanceType": "t3.nano",
                            "State": {"Name": "running"},
                            "PrivateIpAddress": "10.0.1.50",
                            "SecurityGroups": []
                        }
                    ]
                }
            ]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSEC2Collector()
        vms = collector.collect_vm()

        assert len(vms) == 1
        assert vms[0].public_ip is False
        assert vms[0].public_ip_address is None

    @patch("src.aws_collector.boto3")
    def test_ssh_exposure_rule_finding(self, mock_boto3):
        """Test SSH port 22 exposed to 0.0.0.0/0 produces HIGH severity failure."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-ssh-exposed",
                            "PublicIpAddress": "198.51.100.5",
                            "SecurityGroups": [{"GroupId": "sg-ssh"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-ssh",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                }
            ]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()
        results = check_open_ports(vms[0])

        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].severity == "HIGH"
        assert "22" in results[0].message

    @patch("src.aws_collector.boto3")
    def test_rdp_exposure_rule_finding(self, mock_boto3):
        """Test RDP port 3389 exposed to 0.0.0.0/0 produces HIGH severity failure."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-rdp-exposed",
                            "PublicIpAddress": "198.51.100.6",
                            "SecurityGroups": [{"GroupId": "sg-rdp"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-rdp",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                }
            ]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()
        results = check_open_ports(vms[0])

        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].severity == "HIGH"

    @patch("src.aws_collector.boto3")
    def test_safe_https_port_passes(self, mock_boto3):
        """Test HTTPS port 443 from 0.0.0.0/0 is not a risky port violation."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-https-server",
                            "PublicIpAddress": "198.51.100.7",
                            "SecurityGroups": [{"GroupId": "sg-web"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-web",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                }
            ]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()
        results = check_open_ports(vms[0])

        assert len(results) == 1
        assert results[0].status == "PASS"

    @patch("src.aws_collector.boto3")
    def test_ipv6_risky_port_exposure(self, mock_boto3):
        """Test risky port exposed to IPv6 ::/0 is detected."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-ipv6-exposed",
                            "PublicIpAddress": "203.0.113.99",
                            "SecurityGroups": [{"GroupId": "sg-v6"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-v6",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
                        }
                    ]
                }
            ]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()

        assert 22 in vms[0].open_ports

    @patch("src.aws_collector.boto3")
    def test_ebs_unencrypted_fails(self, mock_boto3):
        """Test instance with unencrypted EBS volume fails ENCRYPTION-001."""
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-unencrypted-ebs",
                            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-raw"}}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-raw", "Encrypted": False}]
        }
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()
        result = check_encryption(vms[0])

        assert result.status == "FAIL"

    @patch("src.aws_collector.boto3")
    def test_security_group_error_handled(self, mock_boto3):
        """Test API error in describe_security_groups is handled gracefully."""
        from botocore.exceptions import ClientError
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-sg-err",
                            "SecurityGroups": [{"GroupId": "sg-nonexistent"}]
                        }
                    ]
                }
            ]
        }
        mock_client.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "InvalidGroup.NotFound"}},
            "DescribeSecurityGroups"
        )
        mock_client.meta.region_name = "us-east-1"

        collector = AWSCloudCollector()
        vms = collector.collect_vm()

        assert vms[0].open_ports == []

    @patch("src.aws_collector.boto3")
    def test_ec2_missing_credentials(self, mock_boto3):
        """Test missing AWS credentials during EC2 collection raises ConnectionError."""
        from botocore.exceptions import NoCredentialsError
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        mock_client.describe_instances.side_effect = NoCredentialsError()

        collector = AWSCloudCollector()
        with pytest.raises(ConnectionError, match="credentials were not found"):
            collector.collect_vm()
