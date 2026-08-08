"""Strict SQS/S3 decoding and shared TargetEvent contract parsing."""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus

from .config import GeneratorConfig

_INVALID_PERCENT_ENCODING = re.compile(r"%(?![0-9A-Fa-f]{2})")


class RecordRejection(ValueError):
    """A deterministic, non-retryable input rejection."""

    code = "record_rejected"


class InvalidSqsEnvelope(RecordRejection):
    code = "invalid_sqs_envelope"


class UnexpectedS3Object(RecordRejection):
    code = "unexpected_s3_object"


class MutableS3Object(RecordRejection):
    code = "mutable_s3_object"


class MalformedTargetEvent(RecordRejection):
    code = "malformed_target_event"


@dataclass(frozen=True)
class S3ObjectReference:
    bucket: str
    key: str
    etag: str | None
    version_id: str | None


def _json_mapping(raw: str, *, error_type: type[RecordRejection]) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise error_type("message body is not valid JSON") from error
    if not isinstance(value, Mapping):
        raise error_type("message body must be a JSON object")
    return value


def decode_sqs_s3_record(
    record: Mapping[str, Any],
    config: GeneratorConfig,
) -> S3ObjectReference:
    """Return the sole immutable S3 object referenced by one SQS record."""

    if record.get("eventSource") != "aws:sqs":
        raise InvalidSqsEnvelope("record is not from SQS")
    body = record.get("body")
    if not isinstance(body, str) or not body:
        raise InvalidSqsEnvelope("SQS record body is missing")
    payload = _json_mapping(body, error_type=InvalidSqsEnvelope)

    # S3 can be connected directly to SQS or routed through an SNS notification.
    if "Message" in payload:
        message = payload.get("Message")
        if not isinstance(message, str):
            raise InvalidSqsEnvelope("SNS Message must be a JSON string")
        payload = _json_mapping(message, error_type=InvalidSqsEnvelope)

    notifications = payload.get("Records")
    if not isinstance(notifications, list) or len(notifications) != 1:
        raise InvalidSqsEnvelope("each SQS message must contain exactly one S3 notification")
    notification = notifications[0]
    if not isinstance(notification, Mapping):
        raise InvalidSqsEnvelope("S3 notification must be an object")
    if notification.get("eventSource") != "aws:s3":
        raise InvalidSqsEnvelope("nested record is not from S3")
    event_name = notification.get("eventName")
    if not isinstance(event_name, str) or not event_name.startswith("ObjectCreated:"):
        raise InvalidSqsEnvelope("only S3 object creation events are accepted")

    try:
        s3 = notification["s3"]
        bucket = s3["bucket"]["name"]
        object_data = s3["object"]
        encoded_key = object_data["key"]
    except (KeyError, TypeError) as error:
        raise InvalidSqsEnvelope("S3 notification is incomplete") from error
    if not isinstance(bucket, str) or not isinstance(encoded_key, str):
        raise InvalidSqsEnvelope("S3 bucket and key must be strings")
    if _INVALID_PERCENT_ENCODING.search(encoded_key):
        raise InvalidSqsEnvelope("S3 key has invalid percent encoding")
    try:
        key = unquote_plus(encoded_key, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise InvalidSqsEnvelope("S3 key is not valid UTF-8") from error

    if bucket != config.event_bucket or not key.startswith(config.event_prefix):
        raise UnexpectedS3Object("S3 object is outside the configured source")
    if key == config.event_prefix:
        raise UnexpectedS3Object("S3 object key names only the configured prefix")

    etag = object_data.get("eTag") or object_data.get("etag")
    version_id = object_data.get("versionId")
    if etag is not None and not isinstance(etag, str):
        raise InvalidSqsEnvelope("S3 object ETag must be a string")
    if version_id is not None and not isinstance(version_id, str):
        raise InvalidSqsEnvelope("S3 object version ID must be a string")
    if isinstance(version_id, str) and version_id.lower() == "null":
        version_id = None
    if isinstance(etag, str):
        etag = etag.strip()
        if not etag or "\r" in etag or "\n" in etag:
            raise InvalidSqsEnvelope("S3 object ETag is invalid")
    if isinstance(version_id, str):
        version_id = version_id.strip()
        if not version_id or "\r" in version_id or "\n" in version_id:
            raise InvalidSqsEnvelope("S3 object version ID is invalid")
    if not etag and not version_id:
        raise MutableS3Object("S3 notification must identify an ETag or object version")

    return S3ObjectReference(
        bucket=bucket,
        key=key,
        etag=etag,
        version_id=version_id,
    )


def _without_etag_quotes(value: str) -> str:
    return value.strip().strip('"')


def _load_json_document(content: bytes) -> Mapping[str, Any]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MalformedTargetEvent("TargetEvent object is not UTF-8") from error

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MalformedTargetEvent("TargetEvent contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        document = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise MalformedTargetEvent("TargetEvent object is not valid JSON") from error
    if not isinstance(document, Mapping):
        raise MalformedTargetEvent("TargetEvent must be one JSON object")
    return document


def parse_shared_contract(document: Mapping[str, Any]) -> Any:
    """Parse all fields through the sibling shared contract package."""

    module = importlib.import_module("portscanner_contracts")
    shared_parser = getattr(module, "parse_target_event", None)
    if callable(shared_parser):
        try:
            return shared_parser(document)
        except (KeyError, TypeError, ValueError) as error:
            raise MalformedTargetEvent("TargetEvent failed shared contract validation") from error

    # Compatibility for released contract packages and isolated tests that
    # predate parse_target_event(). New contract packages own the complete
    # event union, including removal tombstones.
    target_event_type = getattr(module, "TargetEvent", None)
    if target_event_type is None:
        models = importlib.import_module("portscanner_contracts.models")
        target_event_type = getattr(models, "TargetEvent", None)
    if target_event_type is None:
        raise RuntimeError("portscanner_contracts does not export TargetEvent")

    parser = getattr(target_event_type, "from_dict", None)
    if parser is None:
        parser = getattr(target_event_type, "model_validate", None)
    if not callable(parser):
        raise RuntimeError("portscanner_contracts.TargetEvent has no supported parser")
    try:
        return parser(document)
    except (KeyError, TypeError, ValueError) as error:
        raise MalformedTargetEvent("TargetEvent failed shared contract validation") from error


def fetch_target_event(
    s3_client: Any,
    reference: S3ObjectReference,
    config: GeneratorConfig,
    *,
    parser: Callable[[Mapping[str, Any]], Any] = parse_shared_contract,
) -> Any:
    """Fetch exactly the notified S3 object and parse one TargetEvent."""

    request: dict[str, Any] = {
        "Bucket": reference.bucket,
        "Key": reference.key,
    }
    if reference.etag:
        request["IfMatch"] = reference.etag
    if reference.version_id:
        request["VersionId"] = reference.version_id
    try:
        response = s3_client.get_object(**request)
    except Exception as error:
        error_response = getattr(error, "response", None)
        error_details = error_response.get("Error") if isinstance(error_response, Mapping) else None
        error_code = error_details.get("Code") if isinstance(error_details, Mapping) else None
        if error_code in {"PreconditionFailed", "412"}:
            raise MutableS3Object("S3 object changed before its immutable read") from error
        raise

    content_length = response.get("ContentLength")
    if content_length is not None:
        try:
            parsed_content_length = int(content_length)
        except (TypeError, ValueError) as error:
            raise RuntimeError("S3 returned an invalid ContentLength") from error
        if parsed_content_length > config.max_event_bytes:
            raise MalformedTargetEvent("TargetEvent object is too large")

    response_etag = response.get("ETag")
    if (
        reference.etag
        and response_etag
        and _without_etag_quotes(str(response_etag)) != _without_etag_quotes(reference.etag)
    ):
        raise MutableS3Object("S3 object ETag changed before it was read")
    response_version = response.get("VersionId")
    if reference.version_id and response_version and str(response_version) != reference.version_id:
        raise MutableS3Object("S3 object version changed before it was read")

    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise RuntimeError("S3 response body is missing")
    try:
        content = body.read(config.max_event_bytes + 1)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(content, bytes):
        raise RuntimeError("S3 response body did not return bytes")
    if len(content) > config.max_event_bytes:
        raise MalformedTargetEvent("TargetEvent object is too large")

    document = _load_json_document(content)
    return parser(document)


def read_target_event(
    record: Mapping[str, Any],
    s3_client: Any,
    config: GeneratorConfig,
    *,
    parser: Callable[[Mapping[str, Any]], Any] = parse_shared_contract,
) -> tuple[S3ObjectReference, Any]:
    reference = decode_sqs_s3_record(record, config)
    return reference, fetch_target_event(
        s3_client,
        reference,
        config,
        parser=parser,
    )
