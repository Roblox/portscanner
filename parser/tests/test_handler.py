from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from act_parser import handler
from act_parser.config import Settings
from act_parser.models import CoverageDeclaration, RawResultReference, ScanEnvelope


def _body_many(bucket: str, keys: list[str]) -> str:
    return json.dumps(
        {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {"name": bucket},
                        "object": {"key": key},
                    },
                }
                for key in keys
            ]
        }
    )


def _body(bucket: str, key: str) -> str:
    return _body_many(bucket, [key])


def _envelope(outcome: str) -> ScanEnvelope:
    now = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    raw = b"<nmaprun>"
    return ScanEnvelope(
        attempt_id=f"attempt-{outcome}",
        result_id="a" * 64,
        run_id="run-1",
        directive_id="b" * 64,
        target_event_id="c" * 64,
        trace_id="trace-1",
        provider="aws",
        target_id="d" * 64,
        generation=1,
        address="192.0.2.10",
        profile="targeted-tcp",
        scanner_version=f"sha256:{'e' * 64}",
        outcome=outcome,
        exit_code=0 if outcome == "complete" else None,
        error_type=None if outcome == "complete" else "discovery_incomplete",
        error_retryable=None if outcome == "complete" else True,
        scan_started_at=now,
        scan_completed_at=now,
        result_uploaded_at=now,
        coverage=tuple(
            CoverageDeclaration.from_mapping(
                {"protocol": "tcp", "ports": ["80"], "complete": outcome == "complete"}
            )
        ),
        declared_open_tcp_ports=(),
        raw_result=RawResultReference(
            bucket="raw-result-test",
            key="raw/result.xml",
            sha256=hashlib.sha256(raw).hexdigest(),
        ),
        enrichment_result=None,
    )


def test_requires_exact_notification_bucket_and_decodes_key() -> None:
    assert handler._s3_records(
        _body("scan-result-test", "results%2Fone+two.json"),
        "scan-result-test",
    ) == [("results/one two.json", None)]
    with pytest.raises(handler.PermanentRecordError):
        handler._s3_records(
            _body("other-test-bucket", "results%2Fone.json"),
            "scan-result-test",
        )


def test_lambda_returns_only_retryable_batch_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )
    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler.boto3, "client", lambda _name: object())

    def process(*, envelope_key: str, **_kwargs: Any) -> None:
        if envelope_key == "retry.json":
            raise handler.RetryableRecordError("retry")
        if envelope_key == "reject.json":
            raise handler.PermanentRecordError("reject")

    monkeypatch.setattr(handler, "_process_scan_result", process)
    event = {
        "Records": [
            {
                "messageId": "success-message",
                "body": _body("scan-result-test", "success.json"),
            },
            {
                "messageId": "retry-message",
                "body": _body("scan-result-test", "retry.json"),
            },
            {
                "messageId": "reject-message",
                "body": _body("scan-result-test", "reject.json"),
            },
        ]
    }

    assert handler.lambda_handler(event, None) == {
        "batchItemFailures": [{"itemIdentifier": "retry-message"}]
    }


def test_one_permanent_object_does_not_block_later_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )
    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler.boto3, "client", lambda _name: object())
    processed: list[str] = []

    def process(*, envelope_key: str, **_kwargs: Any) -> None:
        processed.append(envelope_key)
        if envelope_key == "reject.json":
            raise handler.PermanentRecordError("reject")

    monkeypatch.setattr(handler, "_process_scan_result", process)
    event = {
        "Records": [
            {
                "messageId": "multi-message",
                "body": _body_many(
                    "scan-result-test",
                    ["reject.json", "success.json"],
                ),
            }
        ]
    }

    assert handler.lambda_handler(event, None) == {"batchItemFailures": []}
    assert processed == ["reject.json", "success.json"]


def test_one_malformed_notification_object_does_not_block_later_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )
    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler.boto3, "client", lambda _name: object())
    processed: list[str] = []
    notification = json.loads(_body_many("scan-result-test", ["bad.json", "success.json"]))
    notification["Records"][0] = {"eventSource": "not-s3"}

    monkeypatch.setattr(
        handler,
        "_process_scan_result",
        lambda *, envelope_key, **_kwargs: processed.append(envelope_key),
    )
    event = {
        "Records": [
            {
                "messageId": "multi-message",
                "body": json.dumps(notification),
            }
        ]
    }

    assert handler.lambda_handler(event, None) == {"batchItemFailures": []}
    assert processed == ["success.json"]


def test_multi_object_message_retries_if_any_object_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )
    monkeypatch.setattr(handler, "load_settings", lambda: settings)
    monkeypatch.setattr(handler.boto3, "client", lambda _name: object())
    processed: list[str] = []

    def process(*, envelope_key: str, **_kwargs: Any) -> None:
        processed.append(envelope_key)
        if envelope_key == "retry.json":
            raise handler.RetryableRecordError("retry")

    monkeypatch.setattr(handler, "_process_scan_result", process)
    event = {
        "Records": [
            {
                "messageId": "multi-message",
                "body": _body_many(
                    "scan-result-test",
                    ["retry.json", "success.json"],
                ),
            }
        ]
    }

    assert handler.lambda_handler(event, None) == {
        "batchItemFailures": [{"itemIdentifier": "multi-message"}]
    }
    assert processed == ["retry.json", "success.json"]


def test_malformed_non_complete_xml_records_zero_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b"<nmaprun>"
    monkeypatch.setattr(
        handler,
        "_get_object",
        lambda *_args, **_kwargs: (
            raw,
            hashlib.sha256(raw).hexdigest(),
            "raw-version-1",
        ),
    )
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )

    observations, raw_version, enrichment_version, completion_validated = (
        handler._load_observations(
            s3=object(),
            settings=settings,
            envelope=_envelope("partial"),
        )
    )

    assert observations == []
    assert raw_version == "raw-version-1"
    assert enrichment_version is None
    assert not completion_validated

    with pytest.raises(handler.PermanentRecordError):
        handler._load_observations(
            s3=object(),
            settings=settings,
            envelope=replace(_envelope("complete"), outcome="complete"),
        )


def test_editable_rule_configuration_errors_are_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        scan_result_bucket="scan-result-test",
        raw_result_bucket="raw-result-test",
        finding_bucket="finding-test",
        database_dsn="unused",
    )
    envelope = _envelope("partial")

    class ConnectionContext:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *_args: object) -> None:
            return None

    class InvalidRuleRepository:
        def __init__(self, _connection: object) -> None:
            pass

        def ingest_scan(self, *_args: Any, **_kwargs: Any) -> None:
            raise handler.RuleConfigurationError("operator-edited rule is invalid")

    monkeypatch.setattr(
        handler,
        "_get_object",
        lambda *_args, **_kwargs: (b"{}", hashlib.sha256(b"{}").hexdigest(), None),
    )
    monkeypatch.setattr(handler, "validate_scan_result", lambda _payload: {})
    monkeypatch.setattr(
        handler.ScanEnvelope,
        "from_mapping",
        classmethod(lambda _cls, _payload: envelope),
    )
    monkeypatch.setattr(
        handler,
        "_load_observations",
        lambda **_kwargs: ([], None, None, False),
    )
    monkeypatch.setattr(handler.psycopg, "connect", lambda _dsn: ConnectionContext())
    monkeypatch.setattr(handler, "Repository", InvalidRuleRepository)

    with pytest.raises(handler.RetryableRecordError, match="detection rule"):
        handler._process_scan_result(
            s3=object(),
            settings=settings,
            envelope_key="result.json",
            envelope_version=None,
        )
