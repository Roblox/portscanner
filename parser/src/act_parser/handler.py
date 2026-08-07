"""SQS partial-batch Lambda handler for S3 ScanResult notifications."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote_plus

import boto3
import psycopg
from botocore.exceptions import BotoCoreError, ClientError

from .config import Settings, load_settings
from .contracts import ContractValidationError, validate_scan_result
from .database import (
    AttemptConflictError,
    DataInvariantError,
    Repository,
    UnknownTargetError,
)
from .handoff import HandoffPublisher
from .models import Observation, RawResultReference, ScanEnvelope
from .xml_parser import merge_enrichment_observations, parse_nmap_xml

LOGGER = logging.getLogger(__name__)


class PermanentRecordError(RuntimeError):
    pass


class RetryableRecordError(RuntimeError):
    pass


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
        raise PermanentRecordError("object is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PermanentRecordError("JSON root must be an object")
    return value


def _read_limited(body: Any, limit: int) -> tuple[bytes, str]:
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    try:
        while True:
            chunk = body.read(min(1_048_576, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise PermanentRecordError("S3 object exceeds configured size limit")
            digest.update(chunk)
            chunks.append(chunk)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    return b"".join(chunks), digest.hexdigest()


def _get_object(
    s3: Any,
    *,
    bucket: str,
    key: str,
    version_id: str | None,
    limit: int,
) -> tuple[bytes, str, str | None]:
    request: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if version_id:
        request["VersionId"] = version_id
    try:
        response = s3.get_object(**request)
        content, digest = _read_limited(response["Body"], limit)
    except PermanentRecordError:
        raise
    except (BotoCoreError, ClientError, OSError) as error:
        raise RetryableRecordError("S3 object fetch failed") from error
    return content, digest, response.get("VersionId")


def _s3_records(body: str, expected_bucket: str) -> list[tuple[str, str | None]]:
    try:
        notification = _load_json(body.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise PermanentRecordError("SQS body is not valid text") from error
    records = notification.get("Records")
    if not isinstance(records, list) or not records:
        raise PermanentRecordError("SQS body is not an S3 notification")

    objects: list[tuple[str, str | None]] = []
    for record in records:
        try:
            if record["eventSource"] != "aws:s3":
                raise PermanentRecordError("notification source is not S3")
            if not str(record["eventName"]).startswith("ObjectCreated:"):
                raise PermanentRecordError("notification is not an object creation")
            bucket = record["s3"]["bucket"]["name"]
            object_data = record["s3"]["object"]
            key = unquote_plus(object_data["key"])
            version_id = object_data.get("versionId")
        except PermanentRecordError:
            raise
        except (KeyError, TypeError) as error:
            raise PermanentRecordError("S3 notification is malformed") from error
        if bucket != expected_bucket:
            raise PermanentRecordError("S3 notification bucket is not configured")
        if not key:
            raise PermanentRecordError("S3 notification key is empty")
        objects.append((key, version_id))
    return objects


def _fetch_xml_observations(
    *,
    s3: Any,
    settings: Settings,
    reference: RawResultReference,
    envelope: ScanEnvelope,
    label: str,
) -> tuple[list[Observation], str | None]:
    if reference.bucket != settings.raw_result_bucket:
        raise PermanentRecordError(f"{label} result bucket is not configured")
    xml, actual_hash, version = _get_object(
        s3,
        bucket=reference.bucket,
        key=reference.key,
        version_id=reference.version_id,
        limit=settings.max_xml_bytes,
    )
    if actual_hash != reference.sha256:
        raise RetryableRecordError(f"{label} XML checksum verification failed")
    try:
        observations = parse_nmap_xml(
            xml,
            target_address=envelope.address,
            observed_at=envelope.scan_completed_at,
        )
    except Exception as error:
        raise PermanentRecordError(f"{label} XML normalization failed") from error
    return observations, version


def _load_observations(
    *,
    s3: Any,
    settings: Settings,
    envelope: ScanEnvelope,
) -> tuple[list[Observation], str | None, str | None]:
    if envelope.raw_result is None:
        if envelope.outcome == "complete":
            raise PermanentRecordError("complete scan has no raw XML reference")
        observations: list[Observation] = []
        raw_version = None
    else:
        observations, raw_version = _fetch_xml_observations(
            s3=s3,
            settings=settings,
            reference=envelope.raw_result,
            envelope=envelope,
            label="raw",
        )

    enrichment_version = None
    if envelope.enrichment_result is not None:
        enrichment_observations, enrichment_version = _fetch_xml_observations(
            s3=s3,
            settings=settings,
            reference=envelope.enrichment_result,
            envelope=envelope,
            label="enrichment",
        )
        try:
            observations = merge_enrichment_observations(
                observations,
                enrichment_observations,
                require_complete=envelope.outcome == "complete",
            )
        except ValueError as error:
            raise PermanentRecordError("enrichment XML conflicts with discovery XML") from error
    elif envelope.outcome == "complete" and envelope.declared_open_tcp_ports:
        raise PermanentRecordError("complete open-port scan has no enrichment XML reference")

    if envelope.outcome == "complete":
        parsed_open_ports = tuple(
            sorted(
                observation.port
                for observation in observations
                if observation.protocol == "tcp" and observation.state == "open"
            )
        )
        if parsed_open_ports != envelope.declared_open_tcp_ports:
            raise PermanentRecordError("raw XML open ports conflict with authoritative ScanResult")
    return observations, raw_version, enrichment_version


def _process_scan_result(
    *,
    s3: Any,
    settings: Settings,
    envelope_key: str,
    envelope_version: str | None,
) -> None:
    envelope_bytes, envelope_sha256, fetched_envelope_version = _get_object(
        s3,
        bucket=settings.scan_result_bucket,
        key=envelope_key,
        version_id=envelope_version,
        limit=settings.max_envelope_bytes,
    )
    try:
        validated = validate_scan_result(_load_json(envelope_bytes))
        envelope = ScanEnvelope.from_mapping(validated)
    except ContractValidationError as error:
        raise PermanentRecordError("ScanResult contract validation failed") from error
    except (KeyError, TypeError, ValueError) as error:
        raise PermanentRecordError("validated ScanResult is not usable") from error

    observations, raw_version, enrichment_version = _load_observations(
        s3=s3,
        settings=settings,
        envelope=envelope,
    )

    try:
        with psycopg.connect(settings.database_dsn) as connection:
            repository = Repository(connection)
            result = repository.ingest_scan(
                envelope,
                observations,
                envelope_bucket=settings.scan_result_bucket,
                envelope_key=envelope_key,
                envelope_version=fetched_envelope_version or envelope_version,
                envelope_sha256=envelope_sha256,
                raw_result_version=raw_version,
                enrichment_result_version=enrichment_version,
                finding_bucket=settings.finding_bucket,
            )
            HandoffPublisher(s3, repository).publish_pending(keys=result.handoff_keys)
    except AttemptConflictError as error:
        raise PermanentRecordError("attempt identity conflict") from error
    except UnknownTargetError as error:
        raise RetryableRecordError("target has not arrived yet") from error
    except DataInvariantError as error:
        raise PermanentRecordError("data-plane invariant rejected evidence") from error
    except (psycopg.Error, BotoCoreError, ClientError, OSError) as error:
        raise RetryableRecordError("data-plane operation failed") from error


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    settings = load_settings()
    s3 = boto3.client("s3")
    failures: list[dict[str, str]] = []

    records = event.get("Records")
    if not isinstance(records, list):
        raise PermanentRecordError("Lambda event has no SQS records")
    for record in records:
        message_id = str(record.get("messageId", "missing-message-id"))
        try:
            body = record["body"]
            if not isinstance(body, str):
                raise PermanentRecordError("SQS body must be text")
            for key, version_id in _s3_records(body, settings.scan_result_bucket):
                _process_scan_result(
                    s3=s3,
                    settings=settings,
                    envelope_key=key,
                    envelope_version=version_id,
                )
        except PermanentRecordError:
            LOGGER.error(
                "scan result rejected message_id=%s reason=permanent_validation",
                message_id,
            )
        except Exception:
            LOGGER.error(
                "scan result deferred message_id=%s reason=retryable_processing",
                message_id,
            )
            failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failures}
