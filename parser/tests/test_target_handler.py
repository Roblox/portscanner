from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from act_parser import target_handler
from act_parser.config import TargetEventSettings
from act_parser.contracts import parse_target_event

NOW = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)


def _settings() -> TargetEventSettings:
    return TargetEventSettings(
        target_event_bucket="target-event-test",
        target_event_prefix="target-events/aws/",
        finding_bucket="finding-test",
        database_dsn="unused",
        max_event_bytes=1024,
    )


def _s3_body(
    key: str,
    *,
    bucket: str = "target-event-test",
    etag: str | None = "etag-1",
    version_id: str | None = "version-1",
    records: int = 1,
) -> str:
    object_data: dict[str, Any] = {"key": key}
    if etag is not None:
        object_data["eTag"] = etag
    if version_id is not None:
        object_data["versionId"] = version_id
    record = {
        "eventSource": "aws:s3",
        "eventName": "ObjectCreated:Put",
        "s3": {
            "bucket": {"name": bucket},
            "object": object_data,
        },
    }
    return json.dumps({"Records": [record] * records})


def _sqs_record(message_id: str, key: str, **kwargs: Any) -> dict[str, Any]:
    return {
        "eventSource": "aws:sqs",
        "messageId": message_id,
        "body": _s3_body(key, **kwargs),
    }


def _shared_event(event_type: str = "target.upsert") -> SimpleNamespace:
    source = SimpleNamespace(
        source_event_name="AwsConfigSnapshot",
        source_event_id="source-event-1",
        source_request_id="source-request-1",
        event_time=NOW,
        observed_at=NOW + timedelta(seconds=1),
        collected_at=NOW + timedelta(seconds=2),
    )
    target = SimpleNamespace(
        target_id="target-id-1",
        provider="aws",
        scope_id="123456789012",
        location="us-west-2",
        resource_id="eni-0123456789abcdef0",
        private_address="10.0.0.10",
        public_address="192.0.2.10",
        generation=7,
    )
    context = SimpleNamespace(
        account_id="123456789012",
        region="us-west-2",
        network_interface_id="eni-0123456789abcdef0",
        private_ip="10.0.0.10",
        public_ip="192.0.2.10",
        instance_id="i-0123456789abcdef0",
        security_group_ids=("sg-0123456789abcdef0",),
        policy_fingerprint="a" * 64,
        candidate_tcp_port_ranges=(SimpleNamespace(start=22, end=22),),
        source_event_name="AwsConfigSnapshot",
        source_event_id="source-event-1",
        source_request_id="source-request-1",
        tags=SimpleNamespace(
            application="example",
            environment="test",
            name=None,
            service="api",
        ),
    )
    values: dict[str, Any] = {
        "event_id": "event-id-1",
        "event_type": event_type,
        "target": target,
        "source": source,
        "aws_context": context,
    }
    if event_type == "target.removed":
        values["removed_at"] = NOW + timedelta(seconds=3)
    else:
        values["scan"] = SimpleNamespace(
            requested_at=NOW + timedelta(seconds=3),
            reason="new_target",
        )
    return SimpleNamespace(**values)


def test_decodes_one_exact_immutable_s3_notification() -> None:
    reference = target_handler._decode_sqs_record(
        _sqs_record("message-1", "target-events%2Faws%2Fevent+one.json"),
        _settings(),
    )
    assert reference == target_handler.S3ObjectReference(
        bucket="target-event-test",
        key="target-events/aws/event one.json",
        etag="etag-1",
        version_id="version-1",
    )

    with pytest.raises(target_handler.PermanentRecordError, match="exactly one"):
        target_handler._decode_sqs_record(
            _sqs_record("message-1", "target-events/aws/event.json", records=2),
            _settings(),
        )
    with pytest.raises(target_handler.PermanentRecordError, match="prefix"):
        target_handler._decode_sqs_record(
            _sqs_record("message-1", "other/event.json"),
            _settings(),
        )
    with pytest.raises(target_handler.PermanentRecordError, match="immutable"):
        target_handler._decode_sqs_record(
            _sqs_record(
                "message-1",
                "target-events/aws/event.json",
                etag=None,
                version_id=None,
            ),
            _settings(),
        )


def test_fetches_the_notified_etag_and_version_with_a_byte_bound() -> None:
    class S3:
        request: dict[str, Any] | None = None

        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            self.request = kwargs
            return {
                "Body": BytesIO(b'{"event":"value"}'),
                "ContentLength": 17,
                "ETag": '"etag-1"',
                "VersionId": "version-1",
            }

    s3 = S3()
    reference = target_handler.S3ObjectReference(
        "target-event-test",
        "target-events/aws/event.json",
        '"etag-1"',
        "version-1",
    )
    assert target_handler._fetch_target_event(s3, reference, _settings()) == b'{"event":"value"}'
    assert s3.request == {
        "Bucket": "target-event-test",
        "Key": "target-events/aws/event.json",
        "IfMatch": '"etag-1"',
        "VersionId": "version-1",
    }

    class OversizedS3:
        def get_object(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "Body": BytesIO(b""),
                "ContentLength": 1025,
                "ETag": '"etag-1"',
                "VersionId": "version-1",
            }

    with pytest.raises(target_handler.PermanentRecordError, match="size limit"):
        target_handler._fetch_target_event(OversizedS3(), reference, _settings())


def test_maps_work_and_removal_without_leaking_unapproved_context() -> None:
    work = target_handler._local_target_event(_shared_event())
    assert work.event_type == "upsert"
    assert work.provider_target_id == "us-west-2/eni-0123456789abcdef0/10.0.0.10"
    assert work.addresses == ("192.0.2.10",)
    assert work.generation == 7
    assert work.scan_reason == "new_target"
    assert work.source_event_time == NOW
    assert work.source_observed_at == NOW + timedelta(seconds=1)
    assert work.source_collected_at == NOW + timedelta(seconds=2)
    assert work.dispatched_at == NOW + timedelta(seconds=3)
    assert set(work.context) == {
        "account_id",
        "region",
        "network_interface_id",
        "private_ip",
        "public_ip",
        "instance_id",
        "security_group_ids",
        "policy_fingerprint",
        "candidate_tcp_port_ranges",
        "source_event_name",
        "source_event_id",
        "source_request_id",
        "tags",
    }
    assert work.context["tags"] == {
        "application": "example",
        "environment": "test",
        "service": "api",
    }

    removal = target_handler._local_target_event(_shared_event("target.removed"))
    assert removal.event_type == "remove"
    assert removal.addresses == ()
    assert removal.scan_reason is None
    assert removal.removed_at == NOW + timedelta(seconds=3)
    assert removal.source_observed_at == NOW + timedelta(seconds=1)


@pytest.mark.parametrize(
    ("filename", "event_type", "addresses"),
    [
        ("target-event.json", "upsert", ("192.0.2.44",)),
        ("target-removal.json", "remove", ()),
    ],
)
def test_maps_authoritative_shared_contract_examples(
    filename: str,
    event_type: str,
    addresses: tuple[str, ...],
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    payload = (repository_root / "examples" / filename).read_bytes()

    event = target_handler._local_target_event(parse_target_event(json.loads(payload)))

    assert event.event_type == event_type
    assert event.addresses == addresses
    assert event.provider_target_id == "us-west-2/eni-0123456789abcdef0/10.24.8.17"


def test_processes_removal_and_retries_pending_handoffs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _shared_event("target.removed")
    applied: list[Any] = []
    publish_calls: list[tuple[tuple[str, ...], int]] = []

    class S3:
        def get_object(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "Body": BytesIO(b"{}"),
                "ContentLength": 2,
                "ETag": '"etag-1"',
                "VersionId": "version-1",
            }

    class ConnectionContext:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    class FakeRepository:
        def __init__(self, _connection: object) -> None:
            pass

        def apply_target_event(self, local: Any, *, finding_bucket: str) -> bool:
            applied.append((local, finding_bucket))
            return False

        def pending_target_event_handoff_keys(self, event_id: str) -> tuple[str, ...]:
            assert event_id == "event-id-1"
            return ("handoff-1",)

    class FakePublisher:
        def __init__(self, _s3: object, _repository: object) -> None:
            pass

        def publish_all(self, *, keys: tuple[str, ...], page_size: int = 1000) -> int:
            publish_calls.append((keys, page_size))
            return len(keys)

    monkeypatch.setattr(target_handler, "parse_target_event", lambda _document: event)
    monkeypatch.setattr(target_handler.psycopg, "connect", lambda _dsn: ConnectionContext())
    monkeypatch.setattr(target_handler, "Repository", FakeRepository)
    monkeypatch.setattr(target_handler, "HandoffPublisher", FakePublisher)

    target_handler._process_target_event(
        s3=S3(),
        settings=_settings(),
        reference=target_handler.S3ObjectReference(
            "target-event-test",
            "target-events/aws/event.json",
            "etag-1",
            "version-1",
        ),
    )

    assert applied[0][0].event_type == "remove"
    assert applied[0][1] == "finding-test"
    assert publish_calls == [(("handoff-1",), 1000)]


def test_lambda_redrives_retryable_and_permanent_batch_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(target_handler, "load_target_event_settings", _settings)
    monkeypatch.setattr(target_handler.boto3, "client", lambda _name: object())

    def process(*, reference: target_handler.S3ObjectReference, **_kwargs: Any) -> None:
        if reference.key.endswith("retry.json"):
            raise target_handler.RetryableRecordError("retry")
        if reference.key.endswith("reject.json"):
            raise target_handler.PermanentRecordError("reject")

    monkeypatch.setattr(target_handler, "_process_target_event", process)
    event = {
        "Records": [
            _sqs_record("success-message", "target-events/aws/success.json"),
            _sqs_record("retry-message", "target-events/aws/retry.json"),
            _sqs_record("reject-message", "target-events/aws/reject.json"),
        ]
    }
    assert target_handler.lambda_handler(event, None) == {
        "batchItemFailures": [
            {"itemIdentifier": "retry-message"},
            {"itemIdentifier": "reject-message"},
        ]
    }
