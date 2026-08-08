from __future__ import annotations

import copy
import io
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote_plus

from portscanner_generator.idempotency import (
    ClaimDisposition,
    ClaimResult,
    EventClaim,
)
from portscanner_generator.kubernetes import CreateResult
from portscanner_generator.scanner_resource import TARGET_HASH_LABEL, target_hash

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)


def event_document(
    *,
    generation: int = 3,
    event_type: str = "target.upsert",
    reason: str = "new_target",
    deadline_at: datetime | None = None,
    not_after: datetime | None = None,
) -> dict[str, Any]:
    deadline = deadline_at or NOW + timedelta(minutes=5)
    freshness = not_after or NOW + timedelta(minutes=10)
    return {
        "schema_version": "1.0",
        "event_id": "1" * 64,
        "trace_id": "trace-example-0001",
        "event_type": event_type,
        "provider": "aws",
        "target": {
            "target_id": "2" * 64,
            "provider": "aws",
            "scope_id": "123456789012",
            "location": "us-east-1",
            "resource_id": "eni-0123456789abcdef0",
            "private_address": "10.0.0.10",
            "public_address": "192.0.2.10",
            "generation": generation,
            "address": "192.0.2.10",
            "address_kind": "ipv4",
            "resource_type": "Example::Network::Interface",
            "scope": {"type": "account", "id": "123456789012"},
            "network_id": "network-example",
            "subnet_id": "subnet-example",
            "tags": {"environment": "test"},
            "owner": None,
        },
        "source": {
            "kind": "snapshot",
            "event_id": "source-event-example",
            "event_time": "2030-01-02T03:00:00Z",
            "observed_at": "2030-01-02T03:00:30Z",
            "collected_at": "2030-01-02T03:01:00Z",
            "cursor": None,
        },
        "policy": None,
        "scan": {
            "directive_id": "3" * 64,
            "reason": reason,
            "profile": "fast-full-tcp",
            "priority": 100,
            "deadline_at": deadline.isoformat().replace("+00:00", "Z"),
            "not_after": freshness.isoformat().replace("+00:00", "Z"),
            "tcp_port_ranges": [{"start": 1, "end": 65535}],
        },
        "provider_metadata": {"fixture": "safe"},
    }


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_test_event(document: Mapping[str, Any]) -> Any:
    required = {
        "schema_version",
        "event_id",
        "trace_id",
        "event_type",
        "provider",
        "target",
        "source",
        "scan",
        "provider_metadata",
    }
    if not required.issubset(document):
        raise ValueError("incomplete event")
    target = document["target"]
    source = document["source"]
    scan = document["scan"]
    return SimpleNamespace(
        event_id=document["event_id"],
        trace_id=document["trace_id"],
        event_type=document["event_type"],
        provider=document["provider"],
        target=SimpleNamespace(**target),
        source=SimpleNamespace(
            kind=source["kind"],
            event_id=source["event_id"],
            event_time=_parse_time(source["event_time"]),
            observed_at=_parse_time(source["observed_at"]),
            collected_at=_parse_time(source["collected_at"]),
            cursor=source.get("cursor"),
        ),
        scan=SimpleNamespace(
            directive_id=scan["directive_id"],
            reason=scan["reason"],
            profile=scan["profile"],
            priority=scan["priority"],
            deadline_at=_parse_time(scan["deadline_at"]),
            not_after=_parse_time(scan["not_after"]),
            tcp_port_ranges=tuple(SimpleNamespace(**value) for value in scan["tcp_port_ranges"]),
        ),
        policy=document.get("policy"),
        provider_metadata=document["provider_metadata"],
        schema_version=document["schema_version"],
    )


def sqs_record(
    document: Mapping[str, Any] | str,
    *,
    message_id: str = "message-example-0001",
    bucket: str = "event-fixtures",
    key: str = "target-events/event-example.json",
    etag: str | None = "fixture-etag",
    version_id: str | None = None,
    nested_records: int = 1,
) -> dict[str, Any]:
    object_data: dict[str, Any] = {"key": quote_plus(key)}
    if etag is not None:
        object_data["eTag"] = etag
    if version_id is not None:
        object_data["versionId"] = version_id
    notification = {
        "eventSource": "aws:s3",
        "eventName": "ObjectCreated:Put",
        "s3": {
            "bucket": {"name": bucket},
            "object": object_data,
        },
    }
    body = json.dumps({"Records": [notification] * nested_records})
    return {
        "messageId": message_id,
        "eventSource": "aws:sqs",
        "body": body,
        "_object_content": (document if isinstance(document, str) else json.dumps(document)),
    }


class FakeS3:
    def __init__(self, content: bytes, *, etag: str = "fixture-etag") -> None:
        self.content = content
        self.etag = etag
        self.calls: list[dict[str, Any]] = []

    def get_object(self, **request: Any) -> dict[str, Any]:
        self.calls.append(request)
        response: dict[str, Any] = {
            "Body": io.BytesIO(self.content),
            "ContentLength": len(self.content),
            "ETag": f'"{self.etag}"',
        }
        if "VersionId" in request:
            response["VersionId"] = request["VersionId"]
        return response


class FakeOwnershipService:
    def __init__(
        self,
        state: str,
        *,
        current_generation: int | None = 3,
    ) -> None:
        self.state = state
        self.current_generation = current_generation
        self.calls: list[tuple[Any, int]] = []

    def revalidate(self, target: Any, generation: int) -> Any:
        self.calls.append((target, generation))
        return SimpleNamespace(
            verdict=self.state,
            target_id=target.target_id,
            requested_generation=generation,
            current_generation=self.current_generation,
            reason="fixture",
        )


class FakeClaimStore:
    def __init__(
        self,
        disposition: ClaimDisposition = ClaimDisposition.ACQUIRED,
    ) -> None:
        claim = (
            EventClaim("event#fixture", "event-hash", "owner", 1)
            if disposition is ClaimDisposition.ACQUIRED
            else None
        )
        self.result = ClaimResult(disposition, claim=claim)
        self.acquired: list[dict[str, Any]] = []
        self.completed: list[dict[str, Any]] = []
        self.retryable: list[dict[str, Any]] = []

    def acquire(self, **values: Any) -> ClaimResult:
        self.acquired.append(values)
        return self.result

    def complete(self, claim: EventClaim, **values: Any) -> bool:
        self.completed.append({"claim": claim, **values})
        return True

    def mark_retryable(self, claim: EventClaim, **values: Any) -> bool:
        self.retryable.append({"claim": claim, **values})
        return True


class FakeScannerClient:
    def __init__(
        self,
        *,
        items: list[Mapping[str, Any]] | None = None,
        create_result: CreateResult = CreateResult.CREATED,
    ) -> None:
        self.items = list(items or [])
        self.create_result = create_result
        self.created: list[Mapping[str, Any]] = []
        self.deleted: list[str] = []
        self.delete_requests: list[str] = []
        self.get_requests: list[str] = []
        self.listed_hashes: list[str] = []

    def create(self, body: Mapping[str, Any]) -> CreateResult:
        self.created.append(copy.deepcopy(body))
        return self.create_result

    def get(self, name: str) -> Mapping[str, Any] | None:
        self.get_requests.append(name)
        return next(
            (
                item
                for item in self.items
                if isinstance(item.get("metadata"), Mapping)
                and item["metadata"].get("name") == name
            ),
            None,
        )

    def list_for_target_hash(self, opaque_target_hash: str) -> list[Mapping[str, Any]]:
        self.listed_hashes.append(opaque_target_hash)
        return self.items

    def delete(self, name: str) -> bool:
        self.delete_requests.append(name)
        for index, item in enumerate(self.items):
            metadata = item.get("metadata")
            if isinstance(metadata, Mapping) and metadata.get("name") == name:
                self.items.pop(index)
                self.deleted.append(name)
                return True
        return False


def scanner_item(target_id: str, generation: int, name: str) -> dict[str, Any]:
    return {
        "metadata": {
            "name": name,
            "labels": {TARGET_HASH_LABEL: target_hash(target_id)},
        },
        "spec": {"target": {"generation": generation}},
    }


class ConditionalFailure(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}
        super().__init__("conditional check failed")


class FakeDynamoTable:
    def __init__(self, partition_key: str = "dispatch_id") -> None:
        self.partition_key = partition_key
        self.items: dict[str, dict[str, Any]] = {}

    def put_item(self, **request: Any) -> dict[str, Any]:
        item = copy.deepcopy(request["Item"])
        key = item[self.partition_key]
        if key in self.items:
            raise ConditionalFailure()
        self.items[key] = item
        return {}

    def get_item(self, **request: Any) -> dict[str, Any]:
        key = request["Key"][self.partition_key]
        item = self.items.get(key)
        return {"Item": copy.deepcopy(item)} if item is not None else {}

    def update_item(self, **request: Any) -> dict[str, Any]:
        key = request["Key"][self.partition_key]
        item = self.items.get(key)
        if item is None:
            raise ConditionalFailure()
        values = request["ExpressionAttributeValues"]
        expression = request["UpdateExpression"]

        if "ADD #attempts" in expression:
            can_reclaim = item["eventHash"] == values[":eventHash"] and (
                item["state"] == values[":retryable"]
                or (
                    item["state"] == values[":claimed"] and item["leaseExpiresAt"] <= values[":now"]
                )
            )
            if not can_reclaim:
                raise ConditionalFailure()
            item.update(
                {
                    "state": values[":claimed"],
                    "claimOwner": values[":owner"],
                    "leaseExpiresAt": values[":lease"],
                    "updatedAt": values[":updated"],
                    "expires_at": values[":expires"],
                    "attempts": item.get("attempts", 0) + values[":one"],
                }
            )
            return {}

        owns_claim = (
            item["eventHash"] == values[":eventHash"]
            and item["state"] == values[":claimed"]
            and item["claimOwner"] == values[":owner"]
        )
        if not owns_claim:
            raise ConditionalFailure()
        if ":terminal" in values:
            item.update(
                {
                    "state": values[":terminal"],
                    "updatedAt": values[":updated"],
                    "ownershipVerdict": values[":verdict"],
                    "cancelledCount": values[":cancelled"],
                }
            )
            if ":scanner" in values:
                item["scannerName"] = values[":scanner"]
        else:
            item.update(
                {
                    "state": values[":retryable"],
                    "updatedAt": values[":updated"],
                    "lastErrorCode": values[":error"],
                }
            )
        item.pop("claimOwner", None)
        item.pop("leaseExpiresAt", None)
        return {}
