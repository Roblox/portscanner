from __future__ import annotations

import json
from typing import Any

import pytest
from act_parser import handler
from act_parser.config import Settings


def _body(bucket: str, key: str) -> str:
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
            ]
        }
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
