from __future__ import annotations

from types import SimpleNamespace

import pytest
from act_processor import handler


class _ConnectionContext:
    def __enter__(self) -> object:
        return object()

    def __exit__(self, *_args: object) -> None:
        return None


def test_requires_stable_scheduled_event_id() -> None:
    with pytest.raises(ValueError, match="stable id"):
        handler.lambda_handler({}, None)


def test_runs_full_reconciliation_and_flushes_handoffs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None, bool]] = []

    class FakeRepository:
        def __init__(self, _connection: object) -> None:
            pass

        def reconcile_all(
            self,
            invocation_key: str,
            *,
            finding_bucket: str | None,
            queue_finding_handoffs: bool,
        ) -> object:
            calls.append((invocation_key, finding_bucket, queue_finding_handoffs))
            return SimpleNamespace(
                duplicate=False,
                findings_examined=3,
                handoff_keys=("current-handoff-1", "current-handoff-2"),
            )

    class FakePublisher:
        def __init__(self, _s3: object, _repository: object) -> None:
            pass

    publish_calls: list[tuple[None, int]] = []

    def publish_all(
        self: object,
        *,
        keys: None,
        page_size: int,
    ) -> int:
        publish_calls.append((keys, page_size))
        return 5

    FakePublisher.publish_all = publish_all  # type: ignore[method-assign]
    monkeypatch.setenv("FINDING_BUCKET", "finding-test-bucket")
    monkeypatch.setenv("HANDOFF_PAGE_SIZE", "2")
    monkeypatch.setattr(handler, "database_dsn", lambda: "unused")
    monkeypatch.setattr(handler.psycopg, "connect", lambda _dsn: _ConnectionContext())
    monkeypatch.setattr(handler.boto3, "client", lambda _name: object())
    monkeypatch.setattr(handler, "Repository", FakeRepository)
    monkeypatch.setattr(handler, "HandoffPublisher", FakePublisher)

    result = handler.lambda_handler({"id": "scheduled-run-1"}, None)

    assert calls == [("scheduled-run-1", "finding-test-bucket", True)]
    assert result["findings_examined"] == 3
    assert result["objects_published"] == 5
    assert publish_calls == [(None, 2)]


def test_database_only_reconciliation_skips_s3_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None, bool]] = []

    class FakeRepository:
        def __init__(self, _connection: object) -> None:
            pass

        def reconcile_all(
            self,
            invocation_key: str,
            *,
            finding_bucket: str | None,
            queue_finding_handoffs: bool,
        ) -> object:
            calls.append((invocation_key, finding_bucket, queue_finding_handoffs))
            return SimpleNamespace(duplicate=False, findings_examined=2, handoff_keys=())

    monkeypatch.setenv("FINDING_EXPORT_ENABLED", "false")
    monkeypatch.delenv("FINDING_BUCKET", raising=False)
    monkeypatch.setattr(handler, "database_dsn", lambda: "unused")
    monkeypatch.setattr(handler.psycopg, "connect", lambda _dsn: _ConnectionContext())
    monkeypatch.setattr(handler, "Repository", FakeRepository)
    monkeypatch.setattr(
        handler.boto3,
        "client",
        lambda _name: (_ for _ in ()).throw(AssertionError("S3 client was created")),
    )

    result = handler.lambda_handler({"id": "database-run-1"}, None)

    assert calls == [("database-run-1", None, False)]
    assert result["findings_examined"] == 2
    assert result["objects_published"] == 0


def test_managed_canary_status_returns_only_bounded_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {
        "target_count": 1,
        "event_count": 1,
        "attempt_count": 1,
        "complete_coverage_count": 1,
        "open_exposure_count": 1,
        "low_finding_count": 1,
        "unexpected_high_finding_count": 0,
    }

    class Result:
        def fetchone(self) -> dict[str, int]:
            return row

    class Connection:
        def __init__(self) -> None:
            self.parameters: tuple[object, ...] | None = None

        def execute(self, _query: str, parameters: tuple[object, ...]) -> Result:
            self.parameters = parameters
            return Result()

    class ConnectionContext:
        def __init__(self, connection: Connection) -> None:
            self.connection = connection

        def __enter__(self) -> Connection:
            return self.connection

        def __exit__(self, *_args: object) -> None:
            return None

    connection = Connection()
    environment = {
        "MANAGED_CANARY_ACCOUNT_ID": "123456789012",
        "MANAGED_CANARY_REGION": "us-east-1",
        "MANAGED_CANARY_ENI_ID": "eni-0123456789abcdef0",
        "MANAGED_CANARY_PRIVATE_IP": "10.255.255.4",
        "MANAGED_CANARY_PUBLIC_IP": "203.0.113.10",
        "MANAGED_CANARY_TAG_KEY": "service",
        "MANAGED_CANARY_TAG_VALUE": "test-managed-canary",
        "MANAGED_CANARY_TCP_PORT": "18080",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(handler, "database_dsn", lambda: "credentials-must-not-return")
    monkeypatch.setattr(
        handler.psycopg,
        "connect",
        lambda _dsn: ConnectionContext(connection),
    )

    result = handler.lambda_handler({"operation": "managed-canary-status"}, None)

    assert result == {
        "operation": "managed-canary-status",
        "status": "ready",
        "ready": True,
        **row,
    }
    assert connection.parameters is not None
    assert connection.parameters[-1] == 18080
    assert "credentials-must-not-return" not in repr(result)
    assert "203.0.113.10" not in repr(result)
