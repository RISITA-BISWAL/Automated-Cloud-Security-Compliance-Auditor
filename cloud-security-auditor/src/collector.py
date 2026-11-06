"""Collector module for loading cloud configuration data."""

import json
from pathlib import Path
from typing import List, Dict, Any

from src.models import StorageBucket, VirtualMachine, Database, IAMUser


class CloudCollector:
    """Base collector interface for loading cloud resources."""

    def collect(self) -> List[Dict[str, Any]]:
        """Collect and return raw resource data."""
        raise NotImplementedError


class MockCloudCollector(CloudCollector):
    """Collector that loads mock cloud configuration from JSON file."""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)

    def collect(self) -> List[Dict[str, Any]]:
        """Load mock cloud configuration from JSON file."""
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        try:
            with open(self.config_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")

        if "resources" not in data:
            raise KeyError("Configuration file missing 'resources' key")

        return data["resources"]

    def get_resources(self) -> List[Any]:
        """Collect and parse resources into typed objects."""
        raw_resources = self.collect()
        parsed_resources = []

        for resource in raw_resources:
            if "type" not in resource:
                raise KeyError(f"Resource missing 'type' field: {resource}")

            resource_type = resource["type"]

            if resource_type == "storage":
                parsed_resources.append(StorageBucket(
                    name=resource.get("name", "unknown"),
                    public_access=resource.get("public_access", False),
                    encrypted=resource.get("encrypted", False),
                    region=resource.get("region", "us-east-1"),
                    public_access_block=resource.get("public_access_block", {}),
                    public_policy=resource.get("public_policy", False),
                    public_acl=resource.get("public_acl", False)
                ))
            elif resource_type == "vm":
                parsed_resources.append(VirtualMachine(
                    name=resource.get("name", "unknown"),
                    encrypted=resource.get("encrypted", False),
                    public_ip=resource.get("public_ip", False),
                    open_ports=resource.get("open_ports", []),
                    region=resource.get("region", "us-east-1"),
                    instance_id=resource.get("instance_id"),
                    instance_type=resource.get("instance_type"),
                    public_ip_address=resource.get("public_ip_address"),
                    private_ip_address=resource.get("private_ip_address"),
                    security_groups=resource.get("security_groups", [])
                ))
            elif resource_type == "database":
                parsed_resources.append(Database(
                    name=resource.get("name", "unknown"),
                    encrypted=resource.get("encrypted", False),
                    public_access=resource.get("public_access", resource.get("publicly_accessible", False)),
                    region=resource.get("region", "us-east-1"),
                    engine=resource.get("engine"),
                    engine_version=resource.get("engine_version"),
                    status=resource.get("status"),
                    kms_key_id=resource.get("kms_key_id"),
                    backup_retention_period=resource.get("backup_retention_period"),
                    multi_az=resource.get("multi_az"),
                    vpc_security_groups=resource.get("vpc_security_groups", [])
                ))
            elif resource_type == "iam":
                parsed_resources.append(IAMUser(
                    username=resource.get("username", resource.get("name", "unknown")),
                    role=resource.get("role", "user"),
                    mfa_enabled=resource.get("mfa_enabled", False),
                    arn=resource.get("arn"),
                    user_id=resource.get("user_id"),
                    create_date=resource.get("create_date"),
                    groups=resource.get("groups", []),
                    attached_policies=resource.get("attached_policies", []),
                    inline_policies=resource.get("inline_policies", []),
                    mfa_devices=resource.get("mfa_devices", []),
                    access_keys=resource.get("access_keys", []),
                    console_access=resource.get("console_access"),
                    privileged=resource.get("privileged"),
                    name=resource.get("name")
                ))
            else:
                raise ValueError(f"Unknown resource type: {resource_type}")

        return parsed_resources
