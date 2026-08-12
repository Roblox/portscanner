"""DynamoDB stream dispatcher for immutable TargetEvent objects."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote_plus

from portscanner_contracts import ScanReason, TargetRemoval, canonical_json, parse_target_event

from portscanner_inventory.base import aws_error_code, partial_batch, structured_log
from portscanner_inventory.config import Settings

LOGGER = logging.getLogger(__name__)
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_EVENT_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PAYLOAD_HASH_METADATA = "payload-sha256"
_CONFLICT_CODES = {"ConditionalRequestConflict", "PreconditionFailed"}
_OUTBOX_INDEX_NAME = "entity-event-index"
_DELIVERED_ENTITY = "outbox-delivered"
_LEGACY_DELIVERY_TTL_SECONDS = 604_800


def _attribute(image: Mapping[str, Any], name: str) -> str | None:
    value = image.get(name)
    return str(value["S"]) if isinstance(value, Mapping) and "S" in value else None


def _number_attribute(image: Mapping[str, Any], name: str) -> int | None:
    value = image.get(name)
    if not isinstance(value, Mapping) or "N" not in value:
        return None
    try:
        return int(str(value["N"]))
    except ValueError:
        return None


def _delivery_retention_seconds(image: Mapping[str, Any]) -> int:
    if "delivery_ttl_seconds" not in image:
        return _LEGACY_DELIVERY_TTL_SECONDS
    retention_seconds = _number_attribute(image, "delivery_ttl_seconds")
    if retention_seconds is None or not 86_400 <= retention_seconds <= 31_536_000:
        raise ValueError("outbox delivery retention is invalid")
    return retention_seconds


def _mark_delivered(
    dynamodb_client: Any,
    image: Mapping[str, Any],
    *,
    table_name: str,
    delivered_at: datetime,
) -> None:
    pk = _attribute(image, "pk")
    sk = _attribute(image, "sk")
    event_id = _attribute(image, "event_id")
    retention_seconds = _delivery_retention_seconds(image)
    if (
        not pk
        or not sk
        or not event_id
        or retention_seconds is None
        or not 86_400 <= retention_seconds <= 31_536_000
    ):
        raise ValueError("outbox delivery state is invalid")
    if delivered_at.tzinfo is None:
        raise ValueError("delivery timestamp must include a timezone")
    timestamp = delivered_at.astimezone(UTC)
    try:
        dynamodb_client.update_item(
            TableName=table_name,
            Key={"pk": {"S": pk}, "sk": {"S": sk}},
            UpdateExpression=(
                "SET #entity = :delivered, #delivered_at = :delivered_at, #expires = :expires"
            ),
            ConditionExpression="#entity = :pending AND #event_id = :event_id",
            ExpressionAttributeNames={
                "#entity": "entity",
                "#event_id": "event_id",
                "#delivered_at": "delivered_at",
                "#expires": "expires_at",
            },
            ExpressionAttributeValues={
                ":pending": {"S": "outbox"},
                ":delivered": {"S": _DELIVERED_ENTITY},
                ":event_id": {"S": event_id},
                ":delivered_at": {
                    "S": timestamp.isoformat().replace("+00:00", "Z"),
                },
                ":expires": {
                    "N": str(int(timestamp.timestamp()) + retention_seconds),
                },
            },
        )
    except Exception as error:
        if aws_error_code(error) != "ConditionalCheckFailedException":
            raise
        response = dynamodb_client.get_item(
            TableName=table_name,
            Key={"pk": {"S": pk}, "sk": {"S": sk}},
            ConsistentRead=True,
        )
        item = response.get("Item") if isinstance(response, Mapping) else None
        if (
            not isinstance(item, Mapping)
            or _attribute(item, "entity") != _DELIVERED_ENTITY
            or _attribute(item, "event_id") != event_id
        ):
            raise


def _etag(response: Mapping[str, Any]) -> str | None:
    value = response.get("ETag")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("S3 returned a non-string ETag")
    result = value.strip().strip('"')
    if not result or "\r" in result or "\n" in result:
        raise ValueError("S3 returned an invalid ETag")
    return result


def _version_id(response: Mapping[str, Any]) -> str | None:
    value = response.get("VersionId")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("S3 returned a non-string VersionId")
    result = value.strip()
    if not result or "\r" in result or "\n" in result:
        raise ValueError("S3 returned an invalid VersionId")
    return None if result.lower() == "null" else result


def _verify_existing_object(
    response: Mapping[str, Any],
    body: bytes,
    payload_sha256: str,
) -> None:
    metadata = response.get("Metadata")
    if isinstance(metadata, Mapping):
        normalized = {str(key).lower(): value for key, value in metadata.items()}
        metadata_hash = normalized.get(_PAYLOAD_HASH_METADATA)
        if metadata_hash is not None:
            if (
                not isinstance(metadata_hash, str)
                or _SHA256_RE.fullmatch(metadata_hash) is None
                or not hmac.compare_digest(metadata_hash, payload_sha256)
            ):
                raise ValueError("existing immutable object payload hash does not match")
            return

    existing_etag = _etag(response)
    expected_etag = hashlib.md5(body, usedforsecurity=False).hexdigest()
    if existing_etag is None or not hmac.compare_digest(existing_etag, expected_etag):
        raise ValueError("existing immutable object cannot be verified")


def _notification_body(
    *,
    bucket: str,
    key: str,
    body_size: int,
    etag: str | None,
    version_id: str | None,
) -> str:
    object_data: dict[str, Any] = {
        "key": quote_plus(key, safe=""),
        "size": body_size,
    }
    if etag is not None:
        object_data["eTag"] = etag
    if version_id is not None:
        object_data["versionId"] = version_id
    if etag is None and version_id is None:
        raise ValueError("S3 object has no immutable identity")
    notification = {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "s3SchemaVersion": "1.0",
                    "configurationId": "portscanner-inventory-outbox",
                    "bucket": {"name": bucket},
                    "object": object_data,
                },
            }
        ]
    }
    return json.dumps(
        notification,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def dispatch_record(
    record: Mapping[str, Any],
    s3_client: Any,
    sqs_client: Any,
    *,
    bucket: str,
    prefix: str = "target-events/aws",
    priority_queue_url: str,
    coverage_queue_url: str,
    target_event_queue_url: str,
    dynamodb_client: Any | None = None,
    table_name: str | None = None,
    delivered_at: datetime | None = None,
) -> bool:
    if record.get("eventName") != "INSERT":
        return False
    if (dynamodb_client is None) != (table_name is None):
        raise ValueError("DynamoDB client and table name must be configured together")
    dynamodb = record.get("dynamodb")
    if not isinstance(dynamodb, Mapping):
        raise ValueError("stream record has no DynamoDB image")
    image = dynamodb.get("NewImage")
    if not isinstance(image, Mapping) or _attribute(image, "entity") != "outbox":
        return False
    if dynamodb_client is not None:
        # Validate delivery-tracking identity before any S3/SQS side effect. Legacy
        # pending rows did not carry delivery_ttl_seconds and use the original
        # seven-day retention when finalized.
        pk = _attribute(image, "pk")
        sk = _attribute(image, "sk")
        if not pk or not sk:
            raise ValueError("outbox delivery state is invalid")
        _delivery_retention_seconds(image)
    event_id = _attribute(image, "event_id") or ""
    account_id = _attribute(image, "account_id") or ""
    region = _attribute(image, "region") or ""
    raw = _attribute(image, "event_json")
    if (
        not _EVENT_RE.fullmatch(event_id)
        or not _ACCOUNT_RE.fullmatch(account_id)
        or not _REGION_RE.fullmatch(region)
        or raw is None
    ):
        raise ValueError("outbox identity is invalid")
    event = parse_target_event(raw)
    if event.event_id != event_id:
        raise ValueError("outbox event identity mismatch")
    if event.aws_context.account_id != account_id or event.aws_context.region != region:
        raise ValueError("outbox scope mismatch")

    body = canonical_json(event).encode()
    payload_sha256 = hashlib.sha256(body).hexdigest()
    key = f"{prefix.strip('/')}/{account_id}/{region}/{event_id}.json"
    object_response: Mapping[str, Any]
    try:
        response = s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            IfNoneMatch="*",
            Metadata={_PAYLOAD_HASH_METADATA: payload_sha256},
        )
        object_response = response if isinstance(response, Mapping) else {}
    except Exception as error:
        if aws_error_code(error) not in _CONFLICT_CODES:
            raise
        response = s3_client.head_object(Bucket=bucket, Key=key)
        if not isinstance(response, Mapping):
            raise ValueError("S3 HEAD response is invalid") from error
        _verify_existing_object(response, body, payload_sha256)
        object_response = response

    etag = _etag(object_response)
    version_id = _version_id(object_response)
    if etag is None and version_id is None:
        response = s3_client.head_object(Bucket=bucket, Key=key)
        if not isinstance(response, Mapping):
            raise ValueError("S3 HEAD response is invalid")
        _verify_existing_object(response, body, payload_sha256)
        object_response = response
        etag = _etag(object_response)
        version_id = _version_id(object_response)

    message_body = _notification_body(
        bucket=bucket,
        key=key,
        body_size=len(body),
        etag=etag,
        version_id=version_id,
    )
    routed_queue_url = (
        priority_queue_url
        if isinstance(event, TargetRemoval) or event.scan.reason is not ScanReason.COVERAGE
        else coverage_queue_url
    )
    sqs_client.send_message(QueueUrl=target_event_queue_url, MessageBody=message_body)
    sqs_client.send_message(QueueUrl=routed_queue_url, MessageBody=message_body)
    if dynamodb_client is not None and table_name is not None:
        _mark_delivered(
            dynamodb_client,
            image,
            table_name=table_name,
            delivered_at=delivered_at or datetime.now(UTC),
        )
    return True


class _Runtime:
    def __init__(self, settings: Settings) -> None:
        import boto3

        settings.validate_outbox()
        self.settings = settings
        self.s3 = boto3.client("s3")
        self.sqs = boto3.client("sqs")
        self.dynamodb = boto3.client("dynamodb")

    def process(self, record: Mapping[str, Any]) -> None:
        dispatch_record(
            record,
            self.s3,
            self.sqs,
            bucket=self.settings.event_bucket,
            prefix=self.settings.event_prefix,
            priority_queue_url=self.settings.priority_queue_url,
            coverage_queue_url=self.settings.coverage_queue_url,
            target_event_queue_url=self.settings.target_event_queue_url,
            dynamodb_client=self.dynamodb,
            table_name=self.settings.state_table,
        )

    def replay(self) -> dict[str, int]:
        response = self.dynamodb.query(
            TableName=self.settings.state_table,
            IndexName=_OUTBOX_INDEX_NAME,
            KeyConditionExpression="#entity = :pending",
            ExpressionAttributeNames={"#entity": "entity"},
            ExpressionAttributeValues={":pending": {"S": "outbox"}},
            Limit=self.settings.outbox_replay_batch_size,
        )
        items = response.get("Items") if isinstance(response, Mapping) else None
        if not isinstance(items, list):
            raise ValueError("outbox replay query returned no Items list")
        processed = 0
        failures = 0
        for item in items:
            if not isinstance(item, Mapping):
                failures += 1
                continue
            try:
                if dispatch_record(
                    {"eventName": "INSERT", "dynamodb": {"NewImage": item}},
                    self.s3,
                    self.sqs,
                    bucket=self.settings.event_bucket,
                    prefix=self.settings.event_prefix,
                    priority_queue_url=self.settings.priority_queue_url,
                    coverage_queue_url=self.settings.coverage_queue_url,
                    target_event_queue_url=self.settings.target_event_queue_url,
                    dynamodb_client=self.dynamodb,
                    table_name=self.settings.state_table,
                ):
                    processed += 1
            except Exception:
                failures += 1
                LOGGER.exception("outbox replay item failed")
        if failures:
            raise RuntimeError(f"outbox replay failed for {failures} item(s)")
        return {"processed": processed, "failures": failures}


_RUNTIME: _Runtime | None = None


def _runtime() -> _Runtime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = _Runtime(Settings.from_env(os.environ))
    return _RUNTIME


def lambda_handler(event: Mapping[str, Any], _context: Any, *, runtime: Any | None = None) -> Any:
    selected = runtime or _runtime()
    if event.get("mode") == "replay-outbox":
        result = selected.replay()
        structured_log(LOGGER, "outbox-replay", **result)
        return result
    records = event.get("Records")
    if not isinstance(records, list):
        raise ValueError("outbox handler requires stream records")
    response = partial_batch(records, selected.process)
    structured_log(
        LOGGER,
        "outbox",
        records=len(records),
        failures=len(response["batchItemFailures"]),
    )
    return response
