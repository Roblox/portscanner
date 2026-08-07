from __future__ import annotations

from typing import Any

from portscanner_inventory.aws.resolve import Ec2Resolver
from portscanner_inventory.aws.signals import candidate_tcp_ports, parse_signal
from portscanner_inventory.base import ResolutionStatus

from .helpers import ACCOUNT_ID, REGION, AwsError, eni, security_group


def _cloudtrail(event_name: str, request: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "eventbridge-id",
        "source": "aws.ec2",
        "detail-type": "AWS API Call via CloudTrail",
        "account": ACCOUNT_ID,
        "region": REGION,
        "time": "2026-01-02T03:04:05Z",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": event_name,
            "eventID": "cloudtrail-event-id",
            "requestID": "request-id",
            "requestParameters": request,
            "userIdentity": {"accessKeyId": "must-not-leak"},
        },
    }


def test_signal_parser_allowlists_and_sanitizes_security_group_delta() -> None:
    event = _cloudtrail(
        "AuthorizeSecurityGroupIngress",
        {
            "groupId": "sg-11111111",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 443,
                        "toPort": 443,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            },
            "tagSpecificationSet": {"items": [{"key": "secret", "value": "ignored"}]},
        },
    )

    hint = parse_signal(event)

    assert hint is not None
    assert hint.security_group_ids == ("sg-11111111",)
    assert hint.candidate_ports.ranges == ((443, 443),)
    assert hint.event_time is not None
    assert not hasattr(hint, "user_identity")
    assert "accessKeyId" not in repr(hint)


def test_signal_parser_ignores_non_allowlisted_event() -> None:
    assert parse_signal(_cloudtrail("DescribeInstances", {"instanceId": "i-bbbbbbbb"})) is None


def test_modify_network_interface_only_accepts_security_group_attachments() -> None:
    unrelated = _cloudtrail(
        "ModifyNetworkInterfaceAttribute",
        {
            "networkInterfaceId": "eni-aaaaaaaa",
            "sourceDestCheck": {"value": False},
        },
    )
    attachment = _cloudtrail(
        "ModifyNetworkInterfaceAttribute",
        {
            "networkInterfaceId": "eni-aaaaaaaa",
            "groupSet": {"items": [{"groupId": "sg-11111111"}]},
        },
    )

    assert parse_signal(unrelated) is None
    assert parse_signal(attachment) is not None


def test_detach_signal_retains_only_safe_attachment_identifier() -> None:
    hint = parse_signal(
        _cloudtrail(
            "DetachNetworkInterface",
            {"attachmentId": "eni-attach-eeeeeeee"},
        )
    )

    assert hint is not None
    assert hint.network_interface_attachment_ids == ("eni-attach-eeeeeeee",)


def test_all_protocol_and_unbounded_delta_select_full_tcp() -> None:
    all_protocol = {"ipPermissions": {"items": [{"ipProtocol": "-1"}]}}
    too_large = {"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 1, "toPort": 9000}]}}

    assert candidate_tcp_ports(all_protocol).full_tcp
    assert candidate_tcp_ports(too_large, max_ports=100).full_tcp


def test_tcp_delta_ranges_are_merged_deterministically() -> None:
    request = {
        "ipPermissions": {
            "items": [
                {"ipProtocol": "tcp", "fromPort": 81, "toPort": 90},
                {"ipProtocol": "6", "fromPort": 80, "toPort": 80},
                {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443},
            ]
        }
    }

    assert candidate_tcp_ports(request).ranges == ((80, 90), (443, 443))


class ResolverClient:
    def __init__(self) -> None:
        self.eni_pages = 0

    def describe_network_interfaces(self, **request: Any) -> dict[str, Any]:
        assert request["Filters"][0]["Name"] == "group-id"
        self.eni_pages += 1
        if self.eni_pages == 1:
            return {
                "NetworkInterfaces": [eni(secondary=[("10.0.0.11", "203.0.113.11")])],
                "NextToken": "next",
            }
        assert request["NextToken"] == "next"
        return {
            "NetworkInterfaces": [
                eni(
                    eni_id="eni-bbbbbbbb",
                    private_ip="10.0.1.10",
                    public_ip="203.0.113.20",
                )
            ]
        }

    def describe_security_groups(self, **request: Any) -> dict[str, Any]:
        assert request["GroupIds"] == ["sg-11111111"]
        return {"SecurityGroups": [security_group()]}

    def describe_instances(self, **request: Any) -> dict[str, Any]:
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": instance_id,
                            "State": {"Name": "running"},
                        }
                        for instance_id in request["InstanceIds"]
                    ]
                }
            ]
        }


def test_security_group_resolution_paginates_and_emits_each_public_association() -> None:
    hint = parse_signal(
        _cloudtrail(
            "AuthorizeSecurityGroupIngress",
            {
                "groupId": "sg-11111111",
                "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443}]},
            },
        )
    )
    assert hint is not None
    client = ResolverClient()

    result = Ec2Resolver(lambda _account, _region: client).resolve(hint)

    assert result.status is ResolutionStatus.COMPLETE
    assert len(result.targets) == 3
    assert client.eni_pages == 2
    assert all(target.source_event_id == "cloudtrail-event-id" for target in result.targets)


def test_resolution_errors_are_unknown_not_inactive() -> None:
    class Denied:
        def describe_network_interfaces(self, **_request: Any) -> dict[str, Any]:
            raise AwsError("UnauthorizedOperation")

    hint = parse_signal(
        _cloudtrail("DeleteNetworkInterface", {"networkInterfaceId": "eni-aaaaaaaa"})
    )
    assert hint is not None

    result = Ec2Resolver(lambda _account, _region: Denied()).resolve(hint)

    assert result.status is ResolutionStatus.UNKNOWN
    assert result.targets == ()
