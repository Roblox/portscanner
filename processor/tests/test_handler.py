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
    calls: list[tuple[str, str]] = []

    class FakeRepository:
        def __init__(self, _connection: object) -> None:
            pass

        def reconcile_all(self, invocation_key: str, *, finding_bucket: str) -> object:
            calls.append((invocation_key, finding_bucket))
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

    assert calls == [("scheduled-run-1", "finding-test-bucket")]
    assert result["findings_examined"] == 3
    assert result["objects_published"] == 5
    assert publish_calls == [(None, 2)]
