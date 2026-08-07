from __future__ import annotations

from portscanner_inventory.aws.normalize import (
    canonicalize_ingress_rules,
    lifecycle_is_active,
    lifecycle_matches,
    normalize_network_interface,
    policy_fingerprint,
)

from .helpers import ACCOUNT_ID, REGION, SG_ID, eni, permission


def test_non_object_lifecycle_data_fails_closed() -> None:
    assert not lifecycle_is_active("[]")
    assert not lifecycle_matches("[]", "{}")


def test_rule_canonicalization_ignores_description_and_order() -> None:
    first = [
        permission(443, 443, description="first"),
        {
            "IpProtocol": "6",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "192.0.2.7/24", "Description": "ignored"}],
        },
    ]
    second = [
        {
            "IpRanges": [{"Description": "changed", "CidrIp": "192.0.2.0/24"}],
            "ToPort": 80,
            "FromPort": 80,
            "IpProtocol": "tcp",
        },
        permission(443, 443, description="second"),
    ]

    assert canonicalize_ingress_rules(first) == canonicalize_ingress_rules(second)
    assert policy_fingerprint({SG_ID: first}, [SG_ID]) == policy_fingerprint(
        {SG_ID: second},
        [SG_ID],
    )


def test_policy_fingerprint_is_order_independent_and_tracks_effective_rules() -> None:
    second_group = "sg-22222222"
    groups = {SG_ID: [permission(443)], second_group: [permission(80, 80)]}
    equivalent = {second_group: [permission(443)]}

    assert policy_fingerprint(groups, [SG_ID, second_group]) == policy_fingerprint(
        groups,
        [second_group, SG_ID],
    )
    assert policy_fingerprint(groups, [SG_ID]) == policy_fingerprint(
        equivalent,
        [second_group],
    )
    assert policy_fingerprint(groups, [SG_ID]) != policy_fingerprint(groups, [second_group])


def test_normalizes_every_public_association_and_stable_identity() -> None:
    interface = eni(secondary=[("10.0.0.11", "203.0.113.11")])
    interface["PrivateIpAddresses"].append(
        {
            "PrivateIpAddress": "10.0.0.12",
            "Association": {"PublicIp": "10.1.2.3"},
        }
    )
    values = normalize_network_interface(
        interface,
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups={SG_ID: [permission()]},
    )

    assert [value.private_ip for value in values] == ["10.0.0.10", "10.0.0.11"]
    assert values[0].target_id == (
        "aws:123456789012:us-east-1:eni:eni-aaaaaaaa:private-ip:10.0.0.10"
    )
    assert values[1].target_id.endswith("private-ip:10.0.0.11")


def test_only_allowlisted_tags_enter_normalized_context() -> None:
    target = normalize_network_interface(
        eni(
            tags=[
                {"Key": "application", "Value": "sample"},
                {"Key": "owner", "Value": "must-not-leak"},
                {"Key": "name", "Value": "edge"},
                {"Key": "environment", "Value": "   "},
            ]
        ),
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups={SG_ID: [permission()]},
        allowed_tag_keys=("application", "environment", "name"),
    )[0]

    assert target.tags_dict == {"application": "sample", "name": "edge"}


def test_signature_tracks_only_dispatch_relevant_state() -> None:
    original = normalize_network_interface(
        eni(tags=[{"Key": "name", "Value": "one"}]),
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups={SG_ID: [permission()]},
        allowed_tag_keys=("name",),
    )[0]
    tag_only = normalize_network_interface(
        eni(tags=[{"Key": "name", "Value": "two"}]),
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups={SG_ID: [permission()]},
        allowed_tag_keys=("name",),
    )[0]
    changed_policy = normalize_network_interface(
        eni(),
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups={SG_ID: [permission(80)]},
    )[0]

    assert original.state_signature == tag_only.state_signature
    assert original.state_signature != changed_policy.state_signature
