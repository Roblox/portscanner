# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib

import pytest
from portscanner_scanner.storage import (
    ObjectAlreadyExistsError,
    S3ConditionalWriter,
    StorageConfigurationError,
    build_object_keys,
)


class RecordingS3:
    def __init__(self, *, duplicate: bool = False):
        self.duplicate = duplicate
        self.calls = []

    def put_object(self, **kwargs):
        if self.duplicate:
            error = RuntimeError("precondition")
            error.response = {
                "ResponseMetadata": {"HTTPStatusCode": 412},
                "Error": {"Code": "PreconditionFailed"},
            }
            raise error
        body = kwargs["Body"]
        if hasattr(body, "read"):
            body = body.read()
        self.calls.append({**kwargs, "Body": body})
        return {}


def test_object_keys_are_deterministic_per_event_and_attempt():
    first = build_object_keys("verify/results", "event-001", "attempt-002")
    second = build_object_keys("verify/results", "event-001", "attempt-002")

    assert first == second
    assert first.discovery_xml == (
        "verify/results/events/event-001/attempts/attempt-002/raw/nmap-discovery.xml"
    )
    assert first.envelope_json.endswith("/attempt-002/scan-result.json")


@pytest.mark.parametrize(
    ("prefix", "event_id", "attempt_id"),
    [
        ("../results", "event-001", "attempt-001"),
        ("verify", "event/001", "attempt-001"),
        ("verify", "event-001", "../attempt"),
    ],
)
def test_unsafe_key_components_are_rejected(prefix, event_id, attempt_id):
    with pytest.raises(StorageConfigurationError):
        build_object_keys(prefix, event_id, attempt_id)


def test_conditional_put_includes_sha256_and_never_overwrites(tmp_path):
    client = RecordingS3()
    writer = S3ConditionalWriter(client)
    value = b"raw-nmap-xml"
    path = tmp_path / "raw.xml"
    path.write_bytes(value)

    digest = writer.put_file(
        bucket="configured-results",
        key="verify/raw.xml",
        path=path,
        content_type="application/xml",
    )

    assert digest == hashlib.sha256(value).hexdigest()
    assert client.calls[0]["IfNoneMatch"] == "*"
    assert client.calls[0]["ChecksumAlgorithm"] == "SHA256"
    assert client.calls[0]["Body"] == value


def test_duplicate_conditional_upload_is_explicit():
    writer = S3ConditionalWriter(RecordingS3(duplicate=True))
    with pytest.raises(ObjectAlreadyExistsError):
        writer.put_bytes(
            bucket="configured-results",
            key="verify/result.json",
            value=b"{}",
            content_type="application/json",
        )
