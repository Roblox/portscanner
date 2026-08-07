"""SQS partial-batch Lambda handler for immutable TargetEvent objects."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus

import boto3
import psycopg
from botocore.exceptions import BotoCoreError, ClientError

from .config import TargetEventSettings, load_target_event_settings
from .contracts import ContractValidationError, parse_target_event
from .database import DataInvariantError, Repository
from .handoff import HandoffPublisher, HandoffPublishError
from .models import TargetEvent, parse_timestamp

LOGGER = logging.getLogger(__name__)
_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")
_WORK_EVENT_TYPES = frozenset({"target.upsert", "policy.changed", "rescan.requested"})
_REMOVAL_EVENT_TYPE = "target.removed"
_AWS_TAG_KEYS = ("application", "environment", "name", "service")
_PRECONDITION_FAILED = 412


class PermanentRecordError(RuntimeError):
    """A malformed or mutable input that must be acknowledged."""


class RetryableRecordError(RuntimeError):
    """A transient S3, database, or publication failure."""


@dataclass(frozen=True, slots=True)
class S3ObjectReference:
    bucket: str
    key: str
    etag: str | None
    version_id: str | None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PermanentRecordError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _load_json(data: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_unique_object)
    except PermanentRecordError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermanentRecordError("input is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PermanentRecordError("JSON root must be an object")
    return value


def _clean_optional_identifier(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PermanentRecordError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned or "\r" in cleaned or "\n" in cleaned:
        raise PermanentRecordError(f"{field} is invalid")
    return cleaned


def _decode_sqs_record(  # noqa: PLR0912
    record: Mapping[str, Any],
    settings: TargetEventSettings,
) -> S3ObjectReference:
    if record.get("eventSource") != "aws:sqs":
        raise PermanentRecordError("record is not from SQS")
    body = record.get("body")
    if not isinstance(body, str) or not body:
        raise PermanentRecordError("SQS body must be text")
    try:
        notification = _load_json(body.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise PermanentRecordError("SQS body is not valid text") from error

    records = notification.get("Records")
    if not isinstance(records, list) or len(records) != 1:
        raise PermanentRecordError("SQS body must contain exactly one S3 notification")
    nested = records[0]
    if not isinstance(nested, Mapping):
        raise PermanentRecordError("S3 notification must be an object")
    if nested.get("eventSource") != "aws:s3":
        raise PermanentRecordError("notification source is not S3")
    event_name = nested.get("eventName")
    if not isinstance(event_name, str) or not event_name.startswith("ObjectCreated:"):
        raise PermanentRecordError("notification is not an object creation")

    try:
        bucket = nested["s3"]["bucket"]["name"]
        object_data = nested["s3"]["object"]
        encoded_key = object_data["key"]
    except (KeyError, TypeError) as error:
        raise PermanentRecordError("S3 notification is malformed") from error
    if not isinstance(bucket, str) or not isinstance(object_data, Mapping):
        raise PermanentRecordError("S3 notification bucket or object is malformed")
    if not isinstance(encoded_key, str) or _INVALID_PERCENT_ENCODING.search(encoded_key):
        raise PermanentRecordError("S3 notification key is malformed")
    try:
        key = unquote_plus(encoded_key, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PermanentRecordError("S3 notification key is not valid UTF-8") from error

    if bucket != settings.target_event_bucket:
        raise PermanentRecordError("S3 notification bucket is not configured")
    if not key.startswith(settings.target_event_prefix) or key == settings.target_event_prefix:
        raise PermanentRecordError("S3 notification key is outside the configured prefix")

    etag = _clean_optional_identifier(
        object_data.get("eTag") or object_data.get("etag"),
        "S3 object ETag",
    )
    version_id = _clean_optional_identifier(object_data.get("versionId"), "S3 object version")
    if version_id is not None and version_id.lower() == "null":
        version_id = None
    if etag is None and version_id is None:
        raise PermanentRecordError("S3 notification has no immutable object identity")
    return S3ObjectReference(bucket=bucket, key=key, etag=etag, version_id=version_id)


def _etag_value(value: str) -> str:
    return value.strip().strip('"')


def _read_limited(body: Any, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        while True:
            chunk = body.read(min(1_048_576, limit - size + 1))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise RetryableRecordError("S3 object body did not return bytes")
            size += len(chunk)
            if size > limit:
                raise PermanentRecordError("TargetEvent object exceeds configured size limit")
            chunks.append(chunk)
    except (PermanentRecordError, RetryableRecordError):
        raise
    except OSError as error:
        raise RetryableRecordError("S3 object read failed") from error
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    return b"".join(chunks)


def _fetch_target_event(
    s3: Any,
    reference: S3ObjectReference,
    settings: TargetEventSettings,
) -> bytes:
    request: dict[str, Any] = {"Bucket": reference.bucket, "Key": reference.key}
    if reference.etag is not None:
        request["IfMatch"] = reference.etag
    if reference.version_id is not None:
        request["VersionId"] = reference.version_id
    try:
        response = s3.get_object(**request)
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code", ""))
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"PreconditionFailed", "412"} or status == _PRECONDITION_FAILED:
            raise PermanentRecordError("S3 object changed before its immutable read") from error
        raise RetryableRecordError("S3 object fetch failed") from error
    except (BotoCoreError, OSError) as error:
        raise RetryableRecordError("S3 object fetch failed") from error

    content_length = response.get("ContentLength")
    if content_length is not None:
        try:
            parsed_length = int(content_length)
        except (TypeError, ValueError) as error:
            raise RetryableRecordError("S3 returned an invalid content length") from error
        if parsed_length < 0:
            raise RetryableRecordError("S3 returned an invalid content length")
        if parsed_length > settings.max_event_bytes:
            raise PermanentRecordError("TargetEvent object exceeds configured size limit")

    response_etag = response.get("ETag")
    if reference.etag is not None and (
        not isinstance(response_etag, str)
        or _etag_value(response_etag) != _etag_value(reference.etag)
    ):
        raise PermanentRecordError("S3 object ETag does not match its notification")
    response_version = response.get("VersionId")
    if reference.version_id is not None and (
        not isinstance(response_version, str) or response_version != reference.version_id
    ):
        raise PermanentRecordError("S3 object version does not match its notification")

    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise RetryableRecordError("S3 object response has no readable body")
    return _read_limited(body, settings.max_event_bytes)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        if name not in value:
            raise PermanentRecordError(f"validated TargetEvent is missing {name}")
        return value[name]
    try:
        return getattr(value, name)
    except AttributeError as error:
        raise PermanentRecordError(f"validated TargetEvent is missing {name}") from error


def _optional_field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _text(value: Any, field: str) -> str:
    raw = getattr(value, "value", value)
    if not isinstance(raw, str) or not raw:
        raise PermanentRecordError(f"{field} must be non-empty text")
    return raw


def _timestamp(value: Any, field: str) -> datetime:
    try:
        return parse_timestamp(value, field)
    except (TypeError, ValueError) as error:
        raise PermanentRecordError(f"{field} must be a timezone-aware timestamp") from error


def _items(value: Any, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise PermanentRecordError(f"{field} must be a sequence")
    return value


def _allowlisted_aws_context(value: Any) -> dict[str, Any]:
    tags_value = _field(value, "tags")
    tags: dict[str, str] = {}
    for key in _AWS_TAG_KEYS:
        item = _optional_field(tags_value, key)
        if item is not None:
            tags[key] = _text(item, f"aws_context.tags.{key}")

    security_groups = [
        _text(item, "aws_context.security_group_ids")
        for item in _items(_field(value, "security_group_ids"), "aws_context.security_group_ids")
    ]
    ranges = [
        {
            "start": int(_field(item, "start")),
            "end": int(_field(item, "end")),
        }
        for item in _items(
            _field(value, "candidate_tcp_port_ranges"),
            "aws_context.candidate_tcp_port_ranges",
        )
    ]
    instance_id = _optional_field(value, "instance_id")
    return {
        "account_id": _text(_field(value, "account_id"), "aws_context.account_id"),
        "region": _text(_field(value, "region"), "aws_context.region"),
        "network_interface_id": _text(
            _field(value, "network_interface_id"),
            "aws_context.network_interface_id",
        ),
        "private_ip": _text(_field(value, "private_ip"), "aws_context.private_ip"),
        "public_ip": _text(_field(value, "public_ip"), "aws_context.public_ip"),
        "instance_id": (
            None if instance_id is None else _text(instance_id, "aws_context.instance_id")
        ),
        "security_group_ids": security_groups,
        "policy_fingerprint": _text(
            _field(value, "policy_fingerprint"),
            "aws_context.policy_fingerprint",
        ),
        "candidate_tcp_port_ranges": ranges,
        "source_event_name": _text(
            _field(value, "source_event_name"),
            "aws_context.source_event_name",
        ),
        "source_event_id": _text(
            _field(value, "source_event_id"),
            "aws_context.source_event_id",
        ),
        "source_request_id": _text(
            _field(value, "source_request_id"),
            "aws_context.source_request_id",
        ),
        "tags": tags,
    }


def _local_target_event(value: Any) -> TargetEvent:
    event_type = _text(_field(value, "event_type"), "event_type")
    if event_type not in _WORK_EVENT_TYPES | {_REMOVAL_EVENT_TYPE}:
        raise PermanentRecordError("validated TargetEvent has an unsupported event type")

    target = _field(value, "target")
    source = _field(value, "source")
    context = _allowlisted_aws_context(_field(value, "aws_context"))
    provider = _text(_field(target, "provider"), "target.provider")
    scope_id = _text(_field(target, "scope_id"), "target.scope_id")
    location = _text(_field(target, "location"), "target.location")
    resource_id = _text(_field(target, "resource_id"), "target.resource_id")
    private_address = _text(_field(target, "private_address"), "target.private_address")
    public_address = _text(_field(target, "public_address"), "target.public_address")
    generation = _field(target, "generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise PermanentRecordError("target.generation must be a positive integer")

    source_name = _text(_field(source, "source_event_name"), "source.source_event_name")
    source_event_id = _text(_field(source, "source_event_id"), "source.source_event_id")
    source_request_id = _text(_field(source, "source_request_id"), "source.source_request_id")
    if provider != "aws":
        raise PermanentRecordError("only AWS TargetEvents are supported")
    if (
        scope_id != context["account_id"]
        or location != context["region"]
        or resource_id != context["network_interface_id"]
        or private_address != context["private_ip"]
        or public_address != context["public_ip"]
        or source_name != context["source_event_name"]
        or source_event_id != context["source_event_id"]
        or source_request_id != context["source_request_id"]
    ):
        raise PermanentRecordError("validated TargetEvent AWS fields are inconsistent")

    source_event_time = _timestamp(_field(source, "event_time"), "source.event_time")
    source_observed_at = _timestamp(_field(source, "observed_at"), "source.observed_at")
    source_collected_at = _timestamp(_field(source, "collected_at"), "source.collected_at")
    removed_at = None
    if event_type == _REMOVAL_EVENT_TYPE:
        removed_at = _timestamp(_field(value, "removed_at"), "removed_at")
        dispatched_at = removed_at
        database_event_type = "remove"
        addresses: tuple[str, ...] = ()
    else:
        scan = _field(value, "scan")
        dispatched_at = _timestamp(_field(scan, "requested_at"), "scan.requested_at")
        database_event_type = "upsert"
        addresses = (public_address,)
    if not source_event_time <= source_observed_at <= source_collected_at <= dispatched_at:
        raise PermanentRecordError("TargetEvent timestamps are not ordered")

    return TargetEvent(
        event_id=_text(_field(value, "event_id"), "event_id"),
        target_id=_text(_field(target, "target_id"), "target.target_id"),
        generation=generation,
        event_type=database_event_type,
        provider=provider,
        provider_scope_id=scope_id,
        provider_target_id=f"{location}/{resource_id}/{private_address}",
        location=location,
        addresses=addresses,
        context=context,
        source_event_time=source_event_time,
        source_observed_at=source_observed_at,
        source_collected_at=source_collected_at,
        dispatched_at=dispatched_at,
        removed_at=removed_at,
    )


def _publish_removal_handoffs(
    s3: Any,
    repository: Repository,
    event_id: str,
) -> None:
    keys = repository.pending_target_event_handoff_keys(event_id)
    if not keys:
        return
    publisher = HandoffPublisher(s3, repository)
    while True:
        limit = min(1000, len(keys))
        published = publisher.publish_pending(keys=keys, limit=limit)
        if published < limit:
            return


def _process_target_event(
    *,
    s3: Any,
    settings: TargetEventSettings,
    reference: S3ObjectReference,
) -> None:
    content = _fetch_target_event(s3, reference, settings)
    try:
        shared_event = parse_target_event(_load_json(content))
        event = _local_target_event(shared_event)
    except PermanentRecordError:
        raise
    except ContractValidationError as error:
        raise PermanentRecordError("TargetEvent contract validation failed") from error
    except (KeyError, TypeError, ValueError) as error:
        raise PermanentRecordError("validated TargetEvent is not usable") from error

    try:
        with psycopg.connect(settings.database_dsn) as connection:
            repository = Repository(connection)
            repository.apply_target_event(event, finding_bucket=settings.finding_bucket)
            if event.event_type == "remove":
                _publish_removal_handoffs(s3, repository, event.event_id)
    except DataInvariantError as error:
        raise PermanentRecordError("target event violates a data-plane invariant") from error
    except (psycopg.Error, BotoCoreError, ClientError, HandoffPublishError, OSError) as error:
        raise RetryableRecordError("target event data-plane operation failed") from error


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    settings = load_target_event_settings()
    s3 = boto3.client("s3")
    records = event.get("Records")
    if not isinstance(records, list):
        raise PermanentRecordError("Lambda event has no SQS records")

    failures: list[dict[str, str]] = []
    for record in records:
        message_id = (
            str(record.get("messageId", "missing-message-id"))
            if isinstance(record, Mapping)
            else "missing-message-id"
        )
        try:
            if not isinstance(record, Mapping):
                raise PermanentRecordError("SQS record must be an object")
            reference = _decode_sqs_record(record, settings)
            _process_target_event(s3=s3, settings=settings, reference=reference)
        except PermanentRecordError:
            LOGGER.error(
                "target event rejected message_id=%s reason=permanent_validation",
                message_id,
            )
        except Exception:
            LOGGER.error(
                "target event deferred message_id=%s reason=retryable_processing",
                message_id,
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}
