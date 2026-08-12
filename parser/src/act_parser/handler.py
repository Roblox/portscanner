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
    RuleConfigurationError,
    UnknownTargetError,
)
from .handoff import HandoffPublisher, HandoffPublishError
from .models import CoverageDeclaration, Observation, RawResultReference, ScanEnvelope
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


def _s3_notification_records(body: str) -> list[Any]:
    try:
        notification = _load_json(body.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise PermanentRecordError("SQS body is not valid text") from error
    records = notification.get("Records")
    if not isinstance(records, list) or not records:
        raise PermanentRecordError("SQS body is not an S3 notification")
    return records


def _s3_record(record: Any, expected_bucket: str) -> tuple[str, str | None]:
    try:
        if record["eventSource"] != "aws:s3":
            raise PermanentRecordError("notification source is not S3")
        if not str(record["eventName"]).startswith("ObjectCreated:"):
            raise PermanentRecordError("notification is not an object creation")
        bucket = record["s3"]["bucket"]["name"]
        object_data = record["s3"]["object"]
        encoded_key = object_data["key"]
        version_id = object_data.get("versionId")
    except PermanentRecordError:
        raise
    except (AttributeError, KeyError, TypeError) as error:
        raise PermanentRecordError("S3 notification is malformed") from error
    if not isinstance(encoded_key, str):
        raise PermanentRecordError("S3 notification key is malformed")
    if version_id is not None and not isinstance(version_id, str):
        raise PermanentRecordError("S3 notification version is malformed")
    key = unquote_plus(encoded_key)
    if bucket != expected_bucket:
        raise PermanentRecordError("S3 notification bucket is not configured")
    if not key:
        raise PermanentRecordError("S3 notification key is empty")
    return key, version_id


def _s3_records(body: str, expected_bucket: str) -> list[tuple[str, str | None]]:
    return [_s3_record(record, expected_bucket) for record in _s3_notification_records(body)]


def _fetch_xml_observations(
    *,
    s3: Any,
    settings: Settings,
    reference: RawResultReference,
    envelope: ScanEnvelope,
    label: str,
    coverage: tuple[CoverageDeclaration, ...] | None = None,
    require_complete: bool = False,
    tolerate_malformed: bool = False,
) -> tuple[list[Observation], str | None, bool]:
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
            coverage=coverage,
            require_complete=require_complete,
        )
    except Exception as error:
        if tolerate_malformed:
            LOGGER.warning(
                "%s XML was malformed for non-complete attempt_id=%s; storing zero observations",
                label,
                envelope.attempt_id,
            )
            return [], version, False
        raise PermanentRecordError(f"{label} XML normalization failed") from error
    return observations, version, True


def _load_observations(
    *,
    s3: Any,
    settings: Settings,
    envelope: ScanEnvelope,
) -> tuple[list[Observation], str | None, str | None, bool]:
    complete = envelope.outcome == "complete"
    raw_parse_valid = True
    if envelope.raw_result is None:
        if complete:
            raise PermanentRecordError("complete scan has no raw XML reference")
        observations: list[Observation] = []
        raw_version = None
    else:
        observations, raw_version, raw_parse_valid = _fetch_xml_observations(
            s3=s3,
            settings=settings,
            reference=envelope.raw_result,
            envelope=envelope,
            label="raw",
            coverage=envelope.coverage if complete else None,
            require_complete=complete,
            tolerate_malformed=not complete,
        )

    enrichment_version = None
    enrichment_parse_valid = True
    if envelope.enrichment_result is not None:
        if not complete and not raw_parse_valid:
            return (
                [],
                raw_version,
                envelope.enrichment_result.version_id,
                False,
            )
        enrichment_coverage = tuple(
            CoverageDeclaration(
                protocol="tcp",
                port_spec=str(port),
                port_from=port,
                port_to=port,
                complete=True,
            )
            for port in envelope.declared_open_tcp_ports
        )
        enrichment_observations, enrichment_version, enrichment_parse_valid = (
            _fetch_xml_observations(
                s3=s3,
                settings=settings,
                reference=envelope.enrichment_result,
                envelope=envelope,
                label="enrichment",
                coverage=enrichment_coverage if complete else None,
                require_complete=complete,
                tolerate_malformed=not complete,
            )
        )
        if not raw_parse_valid or not enrichment_parse_valid:
            observations = []
        else:
            try:
                observations = merge_enrichment_observations(
                    observations,
                    enrichment_observations,
                    require_complete=complete,
                )
            except ValueError as error:
                if complete:
                    raise PermanentRecordError(
                        "enrichment XML conflicts with discovery XML"
                    ) from error
                LOGGER.warning(
                    "inconsistent enrichment for non-complete attempt_id=%s; "
                    "storing zero observations",
                    envelope.attempt_id,
                )
                observations = []
    elif complete and envelope.declared_open_tcp_ports:
        raise PermanentRecordError("complete open-port scan has no enrichment XML reference")

    if complete:
        parsed_open_ports = tuple(
            sorted(
                observation.port
                for observation in observations
                if observation.protocol == "tcp" and observation.state == "open"
            )
        )
        if parsed_open_ports != envelope.declared_open_tcp_ports:
            raise PermanentRecordError("raw XML open ports conflict with authoritative ScanResult")
    return observations, raw_version, enrichment_version, complete


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

    observations, raw_version, enrichment_version, xml_completion_validated = _load_observations(
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
                xml_completion_validated=xml_completion_validated,
            )
            HandoffPublisher(s3, repository).publish_all(keys=result.handoff_keys)
    except AttemptConflictError as error:
        raise PermanentRecordError("attempt identity conflict") from error
    except UnknownTargetError as error:
        raise RetryableRecordError("target has not arrived yet") from error
    except RuleConfigurationError as error:
        raise RetryableRecordError("editable detection rule configuration is invalid") from error
    except DataInvariantError as error:
        raise PermanentRecordError("data-plane invariant rejected evidence") from error
    except (
        psycopg.Error,
        BotoCoreError,
        ClientError,
        HandoffPublishError,
        OSError,
    ) as error:
        raise RetryableRecordError("data-plane operation failed") from error


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    settings = load_settings()
    s3 = boto3.client("s3")
    failures: list[dict[str, str]] = []

    records = event.get("Records")
    if not isinstance(records, list):
        raise PermanentRecordError("Lambda event has no SQS records")
    for record in records:
        message_id = (
            str(record.get("messageId", "missing-message-id"))
            if isinstance(record, Mapping)
            else "missing-message-id"
        )
        try:
            if not isinstance(record, Mapping):
                raise PermanentRecordError("SQS record must be an object")
            body = record["body"]
            if not isinstance(body, str):
                raise PermanentRecordError("SQS body must be text")
            object_records = _s3_notification_records(body)
        except PermanentRecordError:
            LOGGER.error(
                "scan result rejected message_id=%s reason=permanent_notification_validation",
                message_id,
            )
            failures.append({"itemIdentifier": message_id})
            continue
        except Exception:
            LOGGER.exception(
                "scan result deferred message_id=%s reason=retryable_notification_processing",
                message_id,
            )
            failures.append({"itemIdentifier": message_id})
            continue

        record_failure = False
        for object_index, object_record in enumerate(object_records):
            try:
                key, version_id = _s3_record(
                    object_record,
                    settings.scan_result_bucket,
                )
            except PermanentRecordError:
                LOGGER.error(
                    "scan result notification object rejected message_id=%s index=%s "
                    "reason=permanent_validation",
                    message_id,
                    object_index,
                )
                record_failure = True
                continue
            try:
                _process_scan_result(
                    s3=s3,
                    settings=settings,
                    envelope_key=key,
                    envelope_version=version_id,
                )
            except PermanentRecordError:
                LOGGER.error(
                    "scan result object rejected message_id=%s key=%s reason=permanent_validation",
                    message_id,
                    key,
                )
                record_failure = True
            except Exception:
                LOGGER.exception(
                    "scan result object deferred message_id=%s key=%s reason=retryable_processing",
                    message_id,
                    key,
                )
                record_failure = True
        if record_failure:
            failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failures}
