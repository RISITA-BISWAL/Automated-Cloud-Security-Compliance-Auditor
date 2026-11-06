"""Resource models for cloud resources."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class StorageBucket:
    """Represents a cloud storage bucket."""
    name: str
    public_access: bool
    encrypted: bool
    region: str = "us-east-1"
    resource_type: str = "storage"
    public_access_block: Optional[dict] = field(default_factory=dict)
    public_policy: bool = False
    public_acl: bool = False

    def to_dict(self) -> dict:
        return {
            "type": self.resource_type,
            "name": self.name,
            "public_access": self.public_access,
            "encrypted": self.encrypted,
            "region": self.region,
            "public_access_block": self.public_access_block if self.public_access_block is not None else {},
            "public_policy": self.public_policy,
            "public_acl": self.public_acl
        }


@dataclass
class VirtualMachine:
    """Represents a virtual machine."""
    name: str
    encrypted: bool
    public_ip: bool
    open_ports: List[int] = field(default_factory=list)
    region: str = "us-east-1"
    resource_type: str = "vm"
    instance_id: Optional[str] = None
    instance_type: Optional[str] = None
    public_ip_address: Optional[str] = None
    private_ip_address: Optional[str] = None
    security_groups: Optional[List[dict]] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "type": self.resource_type,
            "name": self.name,
            "encrypted": self.encrypted,
            "public_ip": self.public_ip,
            "open_ports": self.open_ports,
            "region": self.region
        }
        if self.instance_id:
            d["instance_id"] = self.instance_id
        if self.instance_type:
            d["instance_type"] = self.instance_type
        if self.public_ip_address:
            d["public_ip_address"] = self.public_ip_address
        if self.private_ip_address:
            d["private_ip_address"] = self.private_ip_address
        if self.security_groups is not None:
            d["security_groups"] = self.security_groups
        return d


@dataclass
class Database:
    """Represents a cloud database."""
    name: str
    encrypted: bool
    public_access: bool
    region: str = "us-east-1"
    resource_type: str = "database"
    engine: Optional[str] = None
    engine_version: Optional[str] = None
    status: Optional[str] = None
    kms_key_id: Optional[str] = None
    backup_retention_period: Optional[int] = None
    multi_az: Optional[bool] = None
    vpc_security_groups: Optional[List[dict]] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "type": self.resource_type,
            "name": self.name,
            "encrypted": self.encrypted,
            "public_access": self.public_access,
            "region": self.region,
            "publicly_accessible": self.public_access
        }
        if self.engine is not None:
            d["engine"] = self.engine
        if self.engine_version is not None:
            d["engine_version"] = self.engine_version
        if self.status is not None:
            d["status"] = self.status
        if self.kms_key_id is not None:
            d["kms_key_id"] = self.kms_key_id
        if self.backup_retention_period is not None:
            d["backup_retention_period"] = self.backup_retention_period
        if self.multi_az is not None:
            d["multi_az"] = self.multi_az
        if self.vpc_security_groups is not None:
            d["vpc_security_groups"] = self.vpc_security_groups
        return d


@dataclass
class IAMUser:
    """Represents an IAM user configuration."""
    username: str
    role: str = "user"
    mfa_enabled: bool = False
    resource_type: str = "iam"
    arn: Optional[str] = None
    user_id: Optional[str] = None
    create_date: Optional[str] = None
    groups: Optional[List[str]] = field(default_factory=list)
    attached_policies: Optional[List[dict]] = field(default_factory=list)
    inline_policies: Optional[List[str]] = field(default_factory=list)
    mfa_devices: Optional[List[dict]] = field(default_factory=list)
    access_keys: Optional[List[dict]] = field(default_factory=list)
    console_access: Optional[bool] = None
    privileged: Optional[bool] = None
    name: Optional[str] = None

    def __post_init__(self):
        if not self.name:
            self.name = self.username
        if self.privileged is not None:
            if self.privileged and self.role == "user":
                self.role = "admin"
        elif self.role and self.role.lower() in ["admin", "administrator", "security_admin"]:
            self.privileged = True
        else:
            self.privileged = False

    def to_dict(self) -> dict:
        d = {
            "type": self.resource_type,
            "name": self.name or self.username,
            "username": self.username,
            "role": self.role,
            "mfa_enabled": self.mfa_enabled
        }
        if self.arn:
            d["arn"] = self.arn
        if self.user_id:
            d["user_id"] = self.user_id
        if self.create_date:
            d["create_date"] = self.create_date
        if self.groups is not None:
            d["groups"] = self.groups
        if self.attached_policies is not None:
            d["attached_policies"] = self.attached_policies
        if self.inline_policies is not None:
            d["inline_policies"] = self.inline_policies
        policies = []
        if self.attached_policies:
            policies.extend([p.get("PolicyName", p.get("PolicyArn", "")) for p in self.attached_policies])
        if self.inline_policies:
            policies.extend(self.inline_policies)
        d["policies"] = policies
        if self.access_keys is not None:
            d["access_keys"] = self.access_keys
        if self.mfa_devices is not None:
            d["mfa_devices"] = self.mfa_devices
        if self.console_access is not None:
            d["console_access"] = self.console_access
        if self.privileged is not None:
            d["privileged"] = self.privileged
        return d

