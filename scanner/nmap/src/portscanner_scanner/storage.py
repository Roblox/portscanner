# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Immutable S3 object keys and conditional writes."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

_KEY_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$")
MIN_BUCKET_LENGTH = 3
MAX_BUCKET_LENGTH = 255
ASCII_CONTROL_LIMIT = 32
PRECONDITION_FAILED_STATUS = 412
MAX_OBJECT_KEY_BYTES = 1_024
MAX_OBJECT_BYTES = 64 * 1024 * 1024


class StorageConfigurationError(ValueError):
    """Raised for unsafe bucket, prefix, or identity key configuration."""


class ObjectAlreadyExistsError(RuntimeError):
    """Raised when an immutable object key has already been claimed."""


class ConditionalWriter(Protocol):
    def put_file(
        self,
        *,
        bucket: str,
        key: str,
        path: os.PathLike[str] | str,
        content_type: str,
    ) -> str:
        """Conditionally write a file and return its hexadecimal SHA-256."""

    def put_bytes(
        self,
        *,
        bucket: str,
        key: str,
        value: bytes,
        content_type: str,
    ) -> str:
        """Conditionally write bytes and return their hexadecimal SHA-256."""


@dataclass(frozen=True)
class ObjectKeys:
    discovery_xml: str
    enrichment_xml: str
    envelope_json: str


def _validate_segment(value: str, *, name: str) -> str:
    if not isinstance(value, str) or _KEY_SEGMENT.fullmatch(value) is None:
        raise StorageConfigurationError(f"{name} must be a non-empty object-key-safe identifier")
    return value


def normalize_prefix(prefix: str) -> str:
    if not isinstance(prefix, str):
        raise StorageConfigurationError("S3 prefix must be a string")
    normalized = prefix.strip("/")
    if not normalized:
        raise StorageConfigurationError("S3 prefix cannot be empty")
    parts = normalized.split("/")
    for part in parts:
        _validate_segment(part, name="S3 prefix segment")
    return "/".join(parts)


def validate_bucket(bucket: str) -> str:
    if (
        not isinstance(bucket, str)
        or not MIN_BUCKET_LENGTH <= len(bucket) <= MAX_BUCKET_LENGTH
        or any(character.isspace() or ord(character) < ASCII_CONTROL_LIMIT for character in bucket)
    ):
        raise StorageConfigurationError("S3 bucket configuration is invalid")
    return bucket


def build_object_keys(prefix: str, event_id: str, attempt_id: str) -> ObjectKeys:
    base = (
        f"{normalize_prefix(prefix)}/events/"
        f"{_validate_segment(event_id, name='event_id')}/attempts/"
        f"{_validate_segment(attempt_id, name='attempt_id')}"
    )
    return ObjectKeys(
        discovery_xml=f"{base}/raw/nmap-discovery.xml",
        enrichment_xml=f"{base}/raw/nmap-enrichment.xml",
        envelope_json=f"{base}/scan-result.json",
    )


def _is_precondition_failure(error: Exception) -> bool:
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return False
    metadata = response.get("ResponseMetadata", {})
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, dict) else None
    details = response.get("Error", {})
    code = details.get("Code") if isinstance(details, dict) else None
    return status == PRECONDITION_FAILED_STATUS or code in {"412", "PreconditionFailed"}


def _digests(value: bytes) -> tuple[str, str]:
    raw_digest = hashlib.sha256(value).digest()
    return raw_digest.hex(), base64.b64encode(raw_digest).decode("ascii")


class S3ConditionalWriter:
    """Use only object-scoped conditional PutObject operations."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def _put(
        self,
        *,
        bucket: str,
        key: str,
        body: Any,
        content_type: str,
        hexadecimal_digest: str,
        base64_digest: str,
    ) -> str:
        validate_bucket(bucket)
        if not key or len(key.encode("utf-8")) > MAX_OBJECT_KEY_BYTES:
            raise StorageConfigurationError("S3 object key is invalid")
        try:
            self._client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
                IfNoneMatch="*",
                ChecksumAlgorithm="SHA256",
                ChecksumSHA256=base64_digest,
            )
        except Exception as error:
            if _is_precondition_failure(error):
                raise ObjectAlreadyExistsError("immutable S3 object key already exists") from error
            raise
        return hexadecimal_digest

    def put_file(
        self,
        *,
        bucket: str,
        key: str,
        path: os.PathLike[str] | str,
        content_type: str,
    ) -> str:
        file_path = Path(path)
        value = file_path.read_bytes()
        if not value or len(value) > MAX_OBJECT_BYTES:
            raise StorageConfigurationError("raw object has an invalid size")
        hexadecimal_digest, base64_digest = _digests(value)
        return self._put(
            bucket=bucket,
            key=key,
            body=value,
            content_type=content_type,
            hexadecimal_digest=hexadecimal_digest,
            base64_digest=base64_digest,
        )

    def put_bytes(
        self,
        *,
        bucket: str,
        key: str,
        value: bytes,
        content_type: str,
    ) -> str:
        if not value or len(value) > MAX_OBJECT_BYTES:
            raise StorageConfigurationError("object has an invalid size")
        hexadecimal_digest, base64_digest = _digests(value)
        return self._put(
            bucket=bucket,
            key=key,
            body=value,
            content_type=content_type,
            hexadecimal_digest=hexadecimal_digest,
            base64_digest=base64_digest,
        )
