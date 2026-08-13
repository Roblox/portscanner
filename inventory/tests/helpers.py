from __future__ import annotations

from copy import deepcopy
from typing import Any

from portscanner_inventory.aws.normalize import normalize_network_interface

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
ENI_ID = "eni-aaaaaaaa"
SG_ID = "sg-11111111"
PRIVATE_IP = "10.0.0.10"
PUBLIC_IP = "198.51.100.10"


class AwsError(Exception):
    def __init__(
        self,
        code: str,
        cancellation_reasons: list[str] | None = None,
    ) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        if cancellation_reasons is not None:
            self.response["CancellationReasons"] = [
                {"Code": reason} for reason in cancellation_reasons
            ]


def permission(
    start: int = 443,
    end: int = 443,
    *,
    description: str = "synthetic",
) -> dict[str, Any]:
    return {
        "IpProtocol": "tcp",
        "FromPort": start,
        "ToPort": end,
        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": description}],
    }


def security_group(
    group_id: str = SG_ID,
    permissions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "GroupId": group_id,
        "IpPermissions": permissions if permissions is not None else [permission()],
    }


def eni(
    *,
    eni_id: str = ENI_ID,
    private_ip: str = PRIVATE_IP,
    public_ip: str | None = PUBLIC_IP,
    group_ids: tuple[str, ...] = (SG_ID,),
    status: str = "in-use",
    instance_id: str = "i-bbbbbbbb",
    interface_type: str = "interface",
    tags: list[dict[str, str]] | None = None,
    secondary: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    private_values: list[dict[str, Any]] = []
    primary: dict[str, Any] = {"PrivateIpAddress": private_ip, "Primary": True}
    if public_ip:
        primary["Association"] = {
            "PublicIp": public_ip,
            "AllocationId": "eipalloc-cccccccc",
            "AssociationId": "eipassoc-dddddddd",
        }
    private_values.append(primary)
    for index, (private, public) in enumerate(secondary or ()):
        private_values.append(
            {
                "PrivateIpAddress": private,
                "Primary": False,
                "Association": {
                    "PublicIp": public,
                    "AllocationId": f"eipalloc-{index + 1:08x}",
                    "AssociationId": f"eipassoc-{index + 1:08x}",
                },
            }
        )
    value: dict[str, Any] = {
        "NetworkInterfaceId": eni_id,
        "PrivateIpAddress": private_ip,
        "PrivateIpAddresses": private_values,
        "Status": status,
        "InterfaceType": interface_type,
        "Attachment": {
            "AttachmentId": "eni-attach-eeeeeeee",
            "Status": "attached",
            "InstanceId": instance_id,
        },
        "Groups": [{"GroupId": group_id} for group_id in group_ids],
        "Tags": tags or [],
    }
    if public_ip:
        value["Association"] = deepcopy(primary["Association"])
    return value


def normalized_target(
    *,
    public_ip: str = PUBLIC_IP,
    group_ids: tuple[str, ...] = (SG_ID,),
    permissions: dict[str, list[dict[str, Any]]] | None = None,
    tags: list[dict[str, str]] | None = None,
):
    groups = permissions or {group_id: [permission()] for group_id in group_ids}
    return normalize_network_interface(
        eni(public_ip=public_ip, group_ids=group_ids, tags=tags),
        account_id=ACCOUNT_ID,
        region=REGION,
        security_groups=groups,
        allowed_tag_keys=("application", "environment", "name", "service"),
    )[0]


class FakeDynamo:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.transactions = 0
        self.fail_transactions = 0
        self.transaction_errors: list[str] = []

    @staticmethod
    def _key(item: dict[str, Any]) -> tuple[str, str]:
        return item["pk"]["S"], item["sk"]["S"]

    def get_item(self, *, Key: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        item = self.items.get(self._key(Key))
        return {"Item": deepcopy(item)} if item else {}

    def scan(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Items": [deepcopy(item) for item in self.items.values()]}

    def transact_write_items(self, *, TransactItems: list[dict[str, Any]], **_kwargs: Any) -> None:
        self.transactions += 1
        if self.transaction_errors:
            code = self.transaction_errors.pop(0)
            raise AwsError("TransactionCanceledException", [code])
        if self.fail_transactions:
            self.fail_transactions -= 1
            raise AwsError(
                "TransactionCanceledException",
                ["ConditionalCheckFailed"],
            )
        for operation in TransactItems:
            if "ConditionCheck" in operation:
                check = operation["ConditionCheck"]
                existing = self.items.get(self._key(check["Key"]))
                values = check["ExpressionAttributeValues"]
                if (
                    existing is None
                    or existing["generation"]["N"] != values[":expected"]["N"]
                    or existing["status"]["S"] != values[":active"]["S"]
                ):
                    raise AwsError(
                        "TransactionCanceledException",
                        ["ConditionalCheckFailed", "None"],
                    )
                continue
            put = operation["Put"]
            item = put["Item"]
            key = self._key(item)
            existing = self.items.get(key)
            condition = put.get("ConditionExpression", "")
            if condition == "attribute_not_exists(pk)" and existing is not None:
                raise AwsError(
                    "TransactionCanceledException",
                    ["ConditionalCheckFailed"],
                )
            if condition.startswith("#generation"):
                values = put["ExpressionAttributeValues"]
                expected_generation = values[":expected"]["N"]
                expected_status = values[":status"]["S"]
                if (
                    existing is None
                    or existing["generation"]["N"] != expected_generation
                    or existing["status"]["S"] != expected_status
                    or (
                        ":expected_observed_at" in values
                        and "observed_at" in existing
                        and existing["observed_at"]["S"] != values[":expected_observed_at"]["S"]
                    )
                    or (
                        ":expected_observation_version" in values
                        and "observation_version" in existing
                        and existing["observation_version"]["S"]
                        != values[":expected_observation_version"]["S"]
                    )
                ):
                    raise AwsError(
                        "TransactionCanceledException",
                        ["ConditionalCheckFailed"],
                    )
        for operation in TransactItems:
            if "Put" not in operation:
                continue
            item = deepcopy(operation["Put"]["Item"])
            self.items[self._key(item)] = item

    def put_item(self, *, Item: dict[str, Any], ConditionExpression: str, **kwargs: Any) -> None:
        key = self._key(Item)
        existing = self.items.get(key)
        if existing is not None:
            if "expires_at < :now" in ConditionExpression:
                now = int(kwargs["ExpressionAttributeValues"][":now"]["N"])
                if int(existing["expires_at"]["N"]) >= now:
                    raise AwsError("ConditionalCheckFailedException")
            else:
                raise AwsError("ConditionalCheckFailedException")
        self.items[key] = deepcopy(Item)

    def delete_item(self, *, Key: dict[str, Any], **_kwargs: Any) -> None:
        self.items.pop(self._key(Key), None)
