"""Emit deterministic low-priority coverage events for current targets."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from portscanner_contracts import deterministic_sha256

from portscanner_inventory.base import partial_batch, structured_log, utc_now
from portscanner_inventory.config import Settings
from portscanner_inventory.events import EventSource
from portscanner_inventory.state import DynamoStateStore, ReconcileAction

LOGGER = logging.getLogger(__name__)


def schedule_bucket(now: datetime, bucket_seconds: int) -> tuple[int, datetime]:
    if now.tzinfo is None:
        raise ValueError("schedule time must be timezone aware")
    bucket = int(now.timestamp()) // bucket_seconds
    return bucket, datetime.fromtimestamp(bucket * bucket_seconds, tz=UTC)


def _scheduled_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("scheduled event time is invalid")
    if parsed.tzinfo is None:
        raise ValueError("scheduled event time must be timezone aware")
    return parsed.astimezone(UTC)


def coverage_source(
    event: Mapping[str, Any],
    *,
    now: datetime,
    bucket_seconds: int,
) -> tuple[EventSource, datetime]:
    """Use an EventBridge identity, or a deterministic bucket for direct calls."""

    raw_event_id = event.get("id")
    raw_event_time = event.get("time")
    if raw_event_id is not None or raw_event_time is not None:
        if not isinstance(raw_event_id, str) or not raw_event_id.strip():
            raise ValueError("scheduled EventBridge event has no id")
        scheduled_at = _scheduled_time(raw_event_time)
        source = EventSource(
            name="scheduled-coverage",
            event_id=raw_event_id,
            request_id=deterministic_sha256(
                "portscanner.inventory.coverage-request.v1",
                {"event_id": raw_event_id, "event_time": scheduled_at},
            ),
            event_time=scheduled_at,
            observed_at=scheduled_at,
        )
        return source, scheduled_at

    bucket, scheduled_at = schedule_bucket(now, bucket_seconds)
    source = EventSource(
        name="scheduled-coverage",
        event_id=deterministic_sha256(
            "portscanner.inventory.coverage-bucket.v1",
            {"bucket": bucket, "bucket_seconds": bucket_seconds},
        ),
        request_id=deterministic_sha256(
            "portscanner.inventory.coverage-request.v1",
            {"bucket": bucket, "bucket_seconds": bucket_seconds},
        ),
        event_time=scheduled_at,
        observed_at=scheduled_at,
    )
    return source, scheduled_at


def emit_coverage(
    state: Any,
    *,
    now: datetime,
    bucket_seconds: int,
    event: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    source, scheduled_at = coverage_source(
        event or {},
        now=now,
        bucket_seconds=bucket_seconds,
    )
    emitted = 0
    races = 0
    targets = state.list_current()
    for current in targets:
        result = state.enqueue_coverage(
            current,
            source=source,
            now=scheduled_at,
        )
        if result.event is not None:
            emitted += 1
        elif result.action is ReconcileAction.RACE:
            races += 1
    structured_log(
        LOGGER,
        "rescan",
        targets=len(targets),
        events=emitted,
        failures=races,
    )
    return {"targets": len(targets), "events": emitted, "races": races}


class _Runtime:
    def __init__(self, settings: Settings) -> None:
        import boto3

        settings.validate_state()
        self.settings = settings
        self.state = DynamoStateStore(
            boto3.client("dynamodb"),
            settings.state_table,
            outbox_ttl_seconds=settings.outbox_ttl_seconds,
        )

    def process(self, event: Mapping[str, Any]) -> dict[str, int]:
        return emit_coverage(
            self.state,
            now=utc_now(),
            bucket_seconds=self.settings.rescan_bucket_seconds,
            event=event,
        )


_RUNTIME: _Runtime | None = None


def _runtime() -> _Runtime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = _Runtime(Settings.from_env(os.environ))
    return _RUNTIME


def lambda_handler(
    event: Mapping[str, Any],
    _context: Any,
    *,
    processor: Callable[[Mapping[str, Any]], Any] | None = None,
) -> Any:
    process = processor or _runtime().process
    records = event.get("Records")
    if isinstance(records, list):

        def process_record(record: Mapping[str, Any]) -> None:
            body = json.loads(str(record.get("body") or "{}"))
            if not isinstance(body, Mapping):
                raise ValueError("rescan body must be an object")
            process(body)

        return partial_batch(records, process_record)
    return process(event)
