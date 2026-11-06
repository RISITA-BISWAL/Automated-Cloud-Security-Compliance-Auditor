"""AWS S3 collector for cloud configuration data."""

import json
from typing import List, Dict, Any, Optional

try:
    import boto3
    from botocore.exceptions import NoCredentialsError, ClientError, ProfileNotFound, NoRegionError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from src.models import StorageBucket, VirtualMachine, Database, IAMUser
from config import RISKY_PORTS


class AWSCloudCollector:
    """Collector that fetches S3 bucket, EC2 instance, RDS database, and IAM configuration from AWS.

    This collector is read-only and does not modify any AWS resources.
    """

    def __init__(self, region: str = None):
        """Initialize the AWS collector.

        Args:
            region: AWS region to query. If None, uses default region from
                    AWS configuration.

        Raises:
            ImportError: If boto3 is not installed.
        """
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is not installed. Install it with: pip install boto3"
            )

        session_kwargs = {}
        if region:
            session_kwargs["region_name"] = region

        try:
            session = boto3.Session(**session_kwargs)
            region_name = region or session.region_name or "us-east-1"
            self.s3_client = session.client("s3", region_name=region_name)
            self.s3_resource = session.resource("s3", region_name=region_name)
            self.ec2_client = session.client("ec2", region_name=region_name)
            self.rds_client = session.client("rds", region_name=region_name)
            self.iam_client = session.client("iam")
        except (ProfileNotFound, NoRegionError) as e:
            raise ConnectionError(
                f"AWS configuration error: {e}"
            )

    def _get_public_access_block(self, bucket_name: str) -> Dict[str, bool]:
        """Fetch S3 PublicAccessBlock configuration for a bucket.

        Returns dictionary with BlockPublicAcls, IgnorePublicAcls,
        BlockPublicPolicy, and RestrictPublicBuckets booleans.
        Returns all False if no configuration exists or on error.
        """
        try:
            response = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )
            config = response.get("PublicAccessBlockConfiguration", {})
            return {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False)
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                return {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            raise

    def _is_public_access_blocked(self, bucket_name: str) -> bool:
        """Check if public access is fully blocked for a bucket via PublicAccessBlock."""
        pab = self._get_public_access_block(bucket_name)
        return all([
            pab.get("BlockPublicAcls", False),
            pab.get("IgnorePublicAcls", False),
            pab.get("BlockPublicPolicy", False),
            pab.get("RestrictPublicBuckets", False)
        ])

    def _is_public_principal(self, principal: Any) -> bool:
        """Determine if statement Principal represents a public principal."""
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*":
                return True
            if isinstance(aws_principal, list) and "*" in aws_principal:
                return True
            for k, v in principal.items():
                if v == "*":
                    return True
                if isinstance(v, list) and "*" in v:
                    return True
        if isinstance(principal, list) and "*" in principal:
            return True
        return False

    def _is_public_policy(self, bucket_name: str) -> bool:
        """Check if bucket policy permits public access.

        Returns True if a policy statement allows access to public principal (*).
        Returns False if no policy exists or policy is private.
        Handles ClientErrors gracefully.
        """
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            if not isinstance(response, dict):
                return False
            policy_str = response.get("Policy", "{}")
            if not isinstance(policy_str, (str, bytes, bytearray)):
                return False
            policy = json.loads(policy_str)
            if not isinstance(policy, dict):
                return False
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            if not isinstance(statements, list):
                return False

            for stmt in statements:
                if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal")
                    if self._is_public_principal(principal):
                        return True
            return False
        except (ClientError, json.JSONDecodeError, TypeError, AttributeError) as e:
            if isinstance(e, ClientError):
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ("NoSuchBucketPolicy", "NoSuchBucket", "AccessDenied", "MethodNotAllowed"):
                    return False
                raise
            return False

    def _is_public_acl(self, bucket_name: str) -> bool:
        """Check if bucket ACL grants public access (AllUsers or AuthenticatedUsers).

        Returns True if public grants exist.
        Returns False if ACL is private or on API error.
        """
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            if not isinstance(response, dict):
                return False
            grants = response.get("Grants", [])
            if not isinstance(grants, list):
                return False
            public_groups = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            }
            for grant in grants:
                if isinstance(grant, dict):
                    grantee = grant.get("Grantee", {})
                    if isinstance(grantee, dict) and grantee.get("Type") == "Group" and grantee.get("URI") in public_groups:
                        return True
            return False
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "NoSuchBucket", "NoSuchControl"):
                return False
            raise

    def _is_encrypted(self, bucket_name: str) -> bool:
        """Check if a bucket has server-side encryption configured.

        Returns True if encryption is enabled.
        Returns False if no encryption configuration is found.
        """
        try:
            response = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            return len(rules) > 0
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("ServerSideEncryptionConfigurationNotFoundError",
                              "NoSuchBucket"):
                return False
            raise

    def collect_storage(self) -> List[StorageBucket]:
        """Collect S3 bucket information and return as StorageBucket models.

        Returns:
            List of StorageBucket instances with data from AWS S3.

        Raises:
            ConnectionError: If AWS credentials are not available.
            ConnectionError: If access to S3 is denied.
        """
        try:
            response = self.s3_client.list_buckets()
        except NoCredentialsError:
            raise ConnectionError(
                "AWS credentials were not found. "
                "Configure AWS credentials before using the AWS collector."
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                raise ConnectionError(
                    "Access denied to AWS S3. "
                    "Ensure your credentials have s3:ListBucket and "
                    "s3:GetBucket* permissions."
                )
            raise ConnectionError(f"AWS API error: {e}")

        buckets = response.get("Buckets", [])
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                pab = self._get_public_access_block(bucket_name)
                public_access_blocked = all(pab.values())
                public_policy = self._is_public_policy(bucket_name)
                public_acl = self._is_public_acl(bucket_name)
                encrypted = self._is_encrypted(bucket_name)
            except ClientError:
                pab = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
                public_access_blocked = False
                public_policy = False
                public_acl = False
                encrypted = False

            is_public = (not public_access_blocked) or public_policy or public_acl

            resources.append(StorageBucket(
                name=bucket_name,
                public_access=is_public,
                encrypted=encrypted,
                region=self.s3_client.meta.region_name or "us-east-1",
                public_access_block=pab,
                public_policy=public_policy,
                public_acl=public_acl
            ))

        return resources

    def _get_security_group_open_ports(self, sg_ids: List[str]) -> List[int]:
        """Inspect Security Group ingress rules for 0.0.0.0/0 and ::/0 sources.

        Returns list of open ports exposed to the public.
        """
        if not sg_ids:
            return []

        open_ports = set()
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=sg_ids)
            sgs = response.get("SecurityGroups", [])
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    ip_ranges = rule.get("IpRanges", [])
                    ipv6_ranges = rule.get("Ipv6Ranges", [])
                    is_public = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges) or \
                                any(r.get("CidrIpv6") == "::/0" for r in ipv6_ranges)

                    if is_public:
                        protocol = rule.get("IpProtocol")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        if protocol == "-1":
                            open_ports.update(RISKY_PORTS)
                            open_ports.update([80, 443])
                        elif from_port is not None and to_port is not None:
                            if from_port == to_port:
                                open_ports.add(from_port)
                            elif (to_port - from_port) <= 100:
                                for p in range(from_port, to_port + 1):
                                    open_ports.add(p)
                            else:
                                for p in RISKY_PORTS + [80, 443]:
                                    if from_port <= p <= to_port:
                                        open_ports.add(p)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("InvalidGroup.NotFound", "AccessDenied", "UnauthorizedOperation"):
                return []
            raise

        return sorted(list(open_ports))

    def _check_ebs_encryption(self, volume_ids: List[str]) -> bool:
        """Check if all attached EBS volumes are encrypted.

        Returns True if all volumes are encrypted.
        Returns False if any volume is unencrypted or on API error.
        """
        if not volume_ids:
            return True

        try:
            response = self.ec2_client.describe_volumes(VolumeIds=volume_ids)
            volumes = response.get("Volumes", [])
            if not volumes:
                return False
            for vol in volumes:
                if not vol.get("Encrypted", False):
                    return False
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("InvalidVolume.NotFound", "AccessDenied", "UnauthorizedOperation"):
                return False
            raise

    def collect_vm(self) -> List[VirtualMachine]:
        """Collect EC2 instance information and return as VirtualMachine models.

        Returns:
            List of VirtualMachine instances with data from AWS EC2.

        Raises:
            ConnectionError: If AWS credentials are not available.
            ConnectionError: If access to EC2 is denied.
        """
        try:
            response = self.ec2_client.describe_instances()
        except NoCredentialsError:
            raise ConnectionError(
                "AWS credentials were not found. "
                "Configure AWS credentials before using the AWS collector."
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                raise ConnectionError(
                    "Access denied to AWS EC2. "
                    "Ensure your credentials have ec2:DescribeInstances and "
                    "ec2:DescribeSecurityGroups permissions."
                )
            raise ConnectionError(f"AWS API error: {e}")

        reservations = response.get("Reservations", [])
        resources = []

        for res in reservations:
            for instance in res.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown")
                instance_type = instance.get("InstanceType", "unknown")
                public_ip_addr = instance.get("PublicIpAddress")
                private_ip_addr = instance.get("PrivateIpAddress")
                has_public_ip = bool(public_ip_addr)

                name = instance_id
                for tag in instance.get("Tags", []):
                    if tag.get("Key") == "Name" and tag.get("Value"):
                        name = tag.get("Value")

                sgs = instance.get("SecurityGroups", [])
                sg_ids = [sg.get("GroupId") for sg in sgs if sg.get("GroupId")]
                sg_info = [{"GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName")} for sg in sgs]

                open_ports = self._get_security_group_open_ports(sg_ids) if sg_ids else []

                volume_ids = []
                for bdm in instance.get("BlockDeviceMappings", []):
                    vol_id = bdm.get("Ebs", {}).get("VolumeId")
                    if vol_id:
                        volume_ids.append(vol_id)

                encrypted = self._check_ebs_encryption(volume_ids) if volume_ids else True

                resources.append(VirtualMachine(
                    name=name,
                    encrypted=encrypted,
                    public_ip=has_public_ip,
                    open_ports=open_ports,
                    region=self.ec2_client.meta.region_name or "us-east-1",
                    instance_id=instance_id,
                    instance_type=instance_type,
                    public_ip_address=public_ip_addr,
                    private_ip_address=private_ip_addr,
                    security_groups=sg_info
                ))

        return resources

    def collect_rds(self) -> List[Database]:
        """Collect RDS instance information and return as Database models.

        Returns:
            List of Database instances with data from AWS RDS.

        Raises:
            ConnectionError: If AWS credentials are not available.
            ConnectionError: If access to RDS is denied.
        """
        try:
            response = self.rds_client.describe_db_instances()
        except NoCredentialsError:
            raise ConnectionError(
                "AWS credentials were not found. "
                "Configure AWS credentials before using the AWS collector."
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                raise ConnectionError(
                    "Access denied to AWS RDS. "
                    "Ensure your credentials have rds:DescribeDBInstances permissions."
                )
            raise ConnectionError(f"AWS API error: {e}")

        instances = response.get("DBInstances", [])
        resources = []

        for instance in instances:
            db_identifier = instance.get("DBInstanceIdentifier", "unknown")
            engine = instance.get("Engine", "unknown")
            engine_version = instance.get("EngineVersion")
            status = instance.get("DBInstanceStatus")
            public_access = instance.get("PubliclyAccessible", False)
            encrypted = instance.get("StorageEncrypted", False)
            kms_key_id = instance.get("KmsKeyId")
            backup_retention = instance.get("BackupRetentionPeriod", 0)
            multi_az = instance.get("MultiAZ", False)

            vpcsg_list = []
            for sg in instance.get("VpcSecurityGroups", []):
                vpcsg_list.append({
                    "VpcSecurityGroupId": sg.get("VpcSecurityGroupId"),
                    "Status": sg.get("Status")
                })

            region_name = self.rds_client.meta.region_name or "us-east-1"

            resources.append(Database(
                name=db_identifier,
                encrypted=encrypted,
                public_access=public_access,
                region=region_name,
                engine=engine,
                engine_version=engine_version,
                status=status,
                kms_key_id=kms_key_id,
                backup_retention_period=backup_retention,
                multi_az=multi_az,
                vpc_security_groups=vpcsg_list
            ))

        return resources

    def _get_iam_user_mfa_devices(self, username: str) -> List[dict]:
        try:
            res = self.iam_client.list_mfa_devices(UserName=username)
            devices = []
            for dev in res.get("MFADevices", []):
                devices.append({
                    "SerialNumber": dev.get("SerialNumber"),
                    "EnableDate": str(dev.get("EnableDate")) if dev.get("EnableDate") else None
                })
            return devices
        except (ClientError, AttributeError):
            return []

    def _get_iam_user_access_keys(self, username: str) -> List[dict]:
        try:
            res = self.iam_client.list_access_keys(UserName=username)
            keys = []
            for key in res.get("AccessKeyMetadata", []):
                keys.append({
                    "AccessKeyId": key.get("AccessKeyId"),
                    "Status": key.get("Status"),
                    "CreateDate": str(key.get("CreateDate")) if key.get("CreateDate") else None
                })
            return keys
        except (ClientError, AttributeError):
            return []

    def _get_iam_user_groups(self, username: str) -> List[str]:
        try:
            res = self.iam_client.list_groups_for_user(UserName=username)
            return [g.get("GroupName") for g in res.get("Groups", []) if g.get("GroupName")]
        except (ClientError, AttributeError):
            return []

    def _get_iam_user_attached_policies(self, username: str) -> List[dict]:
        try:
            res = self.iam_client.list_attached_user_policies(UserName=username)
            return [
                {
                    "PolicyName": p.get("PolicyName"),
                    "PolicyArn": p.get("PolicyArn")
                }
                for p in res.get("AttachedPolicies", [])
            ]
        except (ClientError, AttributeError):
            return []

    def _get_iam_user_inline_policies(self, username: str) -> List[str]:
        try:
            res = self.iam_client.list_user_policies(UserName=username)
            return res.get("PolicyNames", [])
        except (ClientError, AttributeError):
            return []

    def _get_iam_user_console_access(self, username: str) -> Optional[bool]:
        try:
            self.iam_client.get_login_profile(UserName=username)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchEntity", "NotFound"):
                return False
            return False
        except (AttributeError, Exception):
            return False

    def _is_iam_user_privileged(self, username: str, groups: List[str], attached_policies: List[dict], inline_policies: List[str]) -> bool:
        admin_policy_keywords = ["administratoraccess", "poweruseraccess", "admin"]
        admin_group_keywords = ["admin", "administrator", "sysadmin", "securityadmin", "superadmin"]

        for p in attached_policies:
            p_name = (p.get("PolicyName") or "").lower()
            p_arn = (p.get("PolicyArn") or "").lower()
            if any(k in p_name or k in p_arn for k in admin_policy_keywords):
                return True

        for pol in inline_policies:
            if any(k in pol.lower() for k in admin_policy_keywords):
                return True

        for g in groups:
            if any(k in g.lower() for k in admin_group_keywords):
                return True
            try:
                grp_policies = self.iam_client.list_attached_group_policies(GroupName=g)
                for gp in grp_policies.get("AttachedPolicies", []):
                    gp_name = (gp.get("PolicyName") or "").lower()
                    gp_arn = (gp.get("PolicyArn") or "").lower()
                    if any(k in gp_name or k in gp_arn for k in admin_policy_keywords):
                        return True
            except (ClientError, AttributeError):
                pass

        return False

    def collect_iam(self) -> List[IAMUser]:
        """Collect IAM user information and return as IAMUser models.

        Returns:
            List of IAMUser instances with data from AWS IAM.

        Raises:
            ConnectionError: If AWS credentials are not available.
            ConnectionError: If access to IAM is denied.
        """
        try:
            response = self.iam_client.list_users()
        except NoCredentialsError:
            raise ConnectionError(
                "AWS credentials were not found. "
                "Configure AWS credentials before using the AWS collector."
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                raise ConnectionError(
                    "Access denied to AWS IAM. "
                    "Ensure your credentials have iam:ListUsers permissions."
                )
            raise ConnectionError(f"AWS API error: {e}")

        users = response.get("Users", [])
        resources = []

        for user in users:
            username = user.get("UserName", "unknown")
            arn = user.get("Arn")
            user_id = user.get("UserId")
            create_date = str(user.get("CreateDate")) if user.get("CreateDate") else None

            mfa_devices = self._get_iam_user_mfa_devices(username)
            mfa_enabled = len(mfa_devices) > 0
            access_keys = self._get_iam_user_access_keys(username)
            groups = self._get_iam_user_groups(username)
            attached_policies = self._get_iam_user_attached_policies(username)
            inline_policies = self._get_iam_user_inline_policies(username)
            console_access = self._get_iam_user_console_access(username)

            is_privileged = self._is_iam_user_privileged(username, groups, attached_policies, inline_policies)
            role = "admin" if is_privileged else "user"

            resources.append(IAMUser(
                username=username,
                role=role,
                mfa_enabled=mfa_enabled,
                arn=arn,
                user_id=user_id,
                create_date=create_date,
                groups=groups,
                attached_policies=attached_policies,
                inline_policies=inline_policies,
                mfa_devices=mfa_devices,
                access_keys=access_keys,
                console_access=console_access,
                privileged=is_privileged,
                name=username
            ))

        return resources

    def collect_all(self, service: str = "all") -> List[Any]:
        """Collect specified AWS resources (storage, vm, rds, iam, or all)."""
        resources = []
        if service in ("all", "s3", "storage"):
            resources.extend(self.collect_storage())
        if service in ("all", "ec2", "vm"):
            resources.extend(self.collect_vm())
        if service in ("all", "rds", "database"):
            resources.extend(self.collect_rds())
        if service in ("all", "iam"):
            resources.extend(self.collect_iam())
        return resources

    def collect(self) -> List[Dict[str, Any]]:
        """Collect resources and return as raw dictionaries.

        Returns:
            List of dictionaries in the internal resource format.
        """
        resources = self.collect_all()
        return [r.to_dict() for r in resources]


class AWSEC2Collector(AWSCloudCollector):
    """Alias for AWSEC2Collector."""
    pass


class AWSRDSCollector(AWSCloudCollector):
    """Alias for AWSRDSCollector."""
    pass


class AWSIAMCollector(AWSCloudCollector):
    """Alias for AWSIAMCollector."""
    pass



