from __future__ import annotations

import json
from collections import deque
from typing import Any

from portscanner_inventory.aws.config_snapshot import (
    NETWORK_INTERFACE_QUERY,
    ConfigSnapshotBackend,
)
from portscanner_inventory.aws.ec2_snapshot import Ec2SnapshotBackend
from portscanner_inventory.base import ScopeCompletion, SnapshotScope

from .helpers import ACCOUNT_ID, ENI_ID, REGION, AwsError, eni, security_group


def _config_record(
    resource_type: str,
    resource_id: str,
    configuration: dict[str, Any],
    *,
    captured_at: str = "2026-01-02T03:04:00Z",
) -> str:
    return json.dumps(
        {
            "accountId": ACCOUNT_ID,
            "awsRegion": REGION,
            "resourceId": resource_id,
            "resourceType": resource_type,
            "configurationItemCaptureTime": captured_at,
            "configuration": configuration,
        }
    )


class ConfigClient:
    def __init__(
        self,
        groups: list[Any],
        enis: list[Any],
    ) -> None:
        self.groups = deque(groups)
        self.enis = deque(enis)
        self.calls: list[dict[str, Any]] = []

    def select_aggregate_resource_config(self, **request: Any) -> dict[str, Any]:
        self.calls.append(request)
        queue = self.groups if "SecurityGroup" in request["Expression"] else self.enis
        value = queue.popleft()
        if isinstance(value, Exception):
            raise value
        return value


def test_config_snapshot_paginates_both_resource_queries() -> None:
    group = _config_record(
        "AWS::EC2::SecurityGroup",
        "sg-11111111",
        security_group(),
    )
    interface = _config_record(
        "AWS::EC2::NetworkInterface",
        ENI_ID,
        eni(tags=[{"Key": "name", "Value": "sample"}]),
    )
    client = ConfigClient(
        groups=[{"Results": [], "NextToken": "g-next"}, {"Results": [group]}],
        enis=[{"Results": [], "NextToken": "e-next"}, {"Results": [interface]}],
    )
    backend = ConfigSnapshotBackend(
        client,
        aggregator_name="example-aggregator",
        allowed_tag_keys=("name",),
    )

    batch = backend.collect()

    assert batch.completion is ScopeCompletion.COMPLETE
    assert batch.pages == 4
    assert len(batch.targets) == 1
    assert batch.targets[0].tags_dict == {"name": "sample"}
    assert [call.get("NextToken") for call in client.calls] == [
        None,
        "g-next",
        None,
        "e-next",
    ]
    assert "configuration.association.publicIp" not in NETWORK_INTERFACE_QUERY


def test_config_snapshot_discovers_secondary_private_ip_eip() -> None:
    group = _config_record(
        "AWS::EC2::SecurityGroup",
        "sg-11111111",
        security_group(),
    )
    interface = _config_record(
        "AWS::EC2::NetworkInterface",
        ENI_ID,
        eni(
            public_ip=None,
            secondary=[("10.0.0.11", "203.0.113.11")],
        ),
    )
    client = ConfigClient(
        groups=[{"Results": [group]}],
        enis=[{"Results": [interface]}],
    )

    batch = ConfigSnapshotBackend(
        client,
        aggregator_name="example-aggregator",
    ).collect()

    assert batch.completion is ScopeCompletion.COMPLETE
    assert [(item.private_ip, item.public_ip) for item in batch.targets] == [
        ("10.0.0.11", "203.0.113.11")
    ]
    assert batch.targets[0].observed_at is not None
    assert batch.targets[0].observed_at.isoformat() == "2026-01-02T03:04:00+00:00"
    assert batch.targets[0].eni_observed_at == batch.targets[0].observed_at
    assert batch.targets[0].security_group_observed_at == (
        ("sg-11111111", batch.targets[0].observed_at),
    )


def test_config_snapshot_ignores_private_only_eni_before_policy_resolution() -> None:
    interface = _config_record(
        "AWS::EC2::NetworkInterface",
        ENI_ID,
        eni(
            public_ip=None,
            group_ids=("sg-deadbeef",),
        ),
    )
    client = ConfigClient(
        groups=[{"Results": []}],
        enis=[{"Results": [interface]}],
    )

    batch = ConfigSnapshotBackend(
        client,
        aggregator_name="example-aggregator",
    ).collect()

    assert batch.completion is ScopeCompletion.COMPLETE
    assert batch.targets == ()
    assert batch.malformed_records == 0


def test_config_page_failure_makes_scope_incomplete_and_keeps_safe_observations() -> None:
    group = _config_record(
        "AWS::EC2::SecurityGroup",
        "sg-11111111",
        security_group(),
    )
    interface = _config_record("AWS::EC2::NetworkInterface", ENI_ID, eni())
    client = ConfigClient(
        groups=[{"Results": [group]}],
        enis=[
            {"Results": [interface], "NextToken": "next"},
            AwsError("ThrottlingException"),
        ],
    )

    batch = ConfigSnapshotBackend(
        client,
        aggregator_name="example-aggregator",
    ).collect()

    assert batch.completion is ScopeCompletion.PARTIAL
    assert len(batch.targets) == 1
    assert batch.failure_code == "ThrottlingException"
    assert not batch.complete


def test_malformed_config_record_explicitly_suppresses_complete_scope() -> None:
    client = ConfigClient(
        groups=[{"Results": ["not-json"]}],
        enis=[{"Results": []}],
    )

    batch = ConfigSnapshotBackend(
        client,
        aggregator_name="example-aggregator",
    ).collect()

    assert batch.completion is ScopeCompletion.PARTIAL
    assert batch.malformed_records == 1


class Ec2Client:
    def __init__(self) -> None:
        self.group_calls = 0
        self.eni_calls = 0
        self.instance_calls = 0

    def describe_security_groups(self, **request: Any) -> dict[str, Any]:
        self.group_calls += 1
        if self.group_calls == 1:
            return {"SecurityGroups": [], "NextToken": "group-next"}
        assert request["NextToken"] == "group-next"
        return {"SecurityGroups": [security_group()]}

    def describe_network_interfaces(self, **request: Any) -> dict[str, Any]:
        self.eni_calls += 1
        if self.eni_calls == 1:
            return {"NetworkInterfaces": [], "NextToken": "eni-next"}
        assert request["NextToken"] == "eni-next"
        return {"NetworkInterfaces": [eni()]}

    def describe_instances(self, **request: Any) -> dict[str, Any]:
        self.instance_calls += 1
        if self.instance_calls == 1:
            return {"Reservations": [], "NextToken": "instance-next"}
        assert request["NextToken"] == "instance-next"
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-bbbbbbbb",
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }


def test_direct_ec2_backend_paginates_and_normalizes() -> None:
    client = Ec2Client()
    backend = Ec2SnapshotBackend(
        client,
        account_id=ACCOUNT_ID,
        region=REGION,
    )

    batch = backend.collect()

    assert batch.completion is ScopeCompletion.COMPLETE
    assert batch.pages == 6
    assert len(batch.targets) == 1
    assert json.loads(batch.targets[0].lifecycle)["instance"] == "running"
    assert client.group_calls == client.eni_calls == 2
    assert client.instance_calls == 2


def test_scope_completion_is_authoritative_only_when_explicit() -> None:
    scope = SnapshotScope(source="ec2", account_id=ACCOUNT_ID, region=REGION)
    assert scope.includes(ACCOUNT_ID, REGION)
    assert not scope.includes(ACCOUNT_ID, "us-west-2")
