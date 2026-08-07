"""Lambda handler for sanitized EC2 control-plane hints."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from portscanner_contracts import deterministic_sha256

from portscanner_inventory.aws.ownership import OwnershipValidator
from portscanner_inventory.aws.resolve import Ec2Resolver
from portscanner_inventory.aws.session import AwsClientFactory
from portscanner_inventory.aws.signals import parse_signal
from portscanner_inventory.base import (
    OwnershipVerdict,
    ResolutionStatus,
    partial_batch,
    structured_log,
    utc_now,
)
from portscanner_inventory.config import Settings
from portscanner_inventory.events import EventSource, signal_source
from portscanner_inventory.state import DynamoStateStore, ReconcileAction

LOGGER = logging.getLogger(__name__)


class SignalResolutionError(RuntimeError):
    pass


def _hint_source(hint: Any, now: datetime) -> EventSource:
    request_id = hint.request_id or deterministic_sha256(
        "portscanner.inventory.signal-request.v1",
        {"event_id": hint.event_id},
    )
    event_time = hint.event_time or now
    if event_time > now:
        event_time = now
    return EventSource(
        name=hint.event_name,
        event_id=hint.event_id,
        request_id=request_id,
        event_time=event_time,
        observed_at=now,
    )


def process_signal(
    event: Mapping[str, Any],
    state: Any,
    resolver: Any,
    ownership: Any,
    *,
    now: datetime,
    dedupe_seconds: int,
    max_port_ranges: int = 32,
    max_ports: int = 8_192,
) -> dict[str, Any]:
    hint = parse_signal(
        event,
        max_port_ranges=max_port_ranges,
        max_ports=max_ports,
    )
    if hint is None:
        return {"status": "ignored", "events": 0}
    if not state.claim_signal(hint.event_id, now=now, ttl_seconds=dedupe_seconds):
        return {"status": "duplicate", "events": 0}

    try:
        prior_candidates = state.find_signal_candidates(hint)
        resolution = resolver.resolve(hint)
        if resolution.status is ResolutionStatus.UNKNOWN:
            raise SignalResolutionError("EC2 signal resolution is unknown")

        changed = 0
        resolved_ids: set[str] = set()
        for target in resolution.targets:
            resolved_ids.add(target.target_id)
            result = state.reconcile(
                target,
                source=signal_source(target, now),
                now=now,
            )
            if result.action is ReconcileAction.RACE:
                raise SignalResolutionError("target generation race")
            if result.action in {ReconcileAction.ADDED, ReconcileAction.CHANGED}:
                changed += 1

        source = _hint_source(hint, now)
        for candidate in prior_candidates:
            if candidate.target_id in resolved_ids:
                continue
            check = ownership.validate(candidate.target_id, candidate.generation)
            if check.verdict in {OwnershipVerdict.INACTIVE, OwnershipVerdict.MOVED}:
                result = state.remove(candidate, source=source, now=now)
                if result.action is ReconcileAction.REMOVED:
                    changed += 1
            elif check.verdict is OwnershipVerdict.STALE and check.current is not None:
                current = check.current.with_signal(
                    event_name=hint.event_name,
                    event_id=hint.event_id,
                    request_id=hint.request_id,
                    event_time=hint.event_time,
                    candidate_ports=hint.candidate_ports,
                )
                result = state.reconcile(
                    current,
                    source=signal_source(current, now),
                    now=now,
                )
                if result.action is ReconcileAction.RACE:
                    raise SignalResolutionError("target generation race")
                if result.action is ReconcileAction.CHANGED:
                    changed += 1
        structured_log(LOGGER, "signal", status="processed", events=changed)
        return {
            "status": "processed",
            "events": changed,
            "targets": len(resolution.targets),
        }
    except Exception:
        state.release_signal(hint.event_id)
        raise


class _Runtime:
    def __init__(self, settings: Settings) -> None:
        import boto3

        settings.validate_state()
        session = boto3.Session()
        state = DynamoStateStore(
            session.client("dynamodb"),
            settings.state_table,
            outbox_ttl_seconds=settings.outbox_ttl_seconds,
        )
        factory = AwsClientFactory(
            session,
            role_arn_template=settings.discovery_role_arn_template,
            external_id=settings.external_id,
            local_account_id=settings.account_id,
        )
        self.settings = settings
        self.state = state
        self.resolver = Ec2Resolver(
            factory,
            allowed_tag_keys=settings.allowed_tag_keys,
        )
        self.ownership = OwnershipValidator(
            state,
            factory,
            allowed_tag_keys=settings.allowed_tag_keys,
        )

    def process(self, event: Mapping[str, Any]) -> dict[str, Any]:
        return process_signal(
            event,
            self.state,
            self.resolver,
            self.ownership,
            now=utc_now(),
            dedupe_seconds=self.settings.signal_dedupe_seconds,
            max_port_ranges=self.settings.max_signal_port_ranges,
            max_ports=self.settings.max_signal_ports,
        )


_RUNTIME: _Runtime | None = None


def _runtime() -> _Runtime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = _Runtime(Settings.from_env(os.environ))
    return _RUNTIME


def _body(record: Mapping[str, Any]) -> Mapping[str, Any]:
    parsed = json.loads(str(record.get("body") or "{}"))
    if isinstance(parsed, Mapping) and isinstance(parsed.get("Message"), str):
        parsed = json.loads(parsed["Message"])
    if not isinstance(parsed, Mapping):
        raise ValueError("signal body must be an object")
    return parsed


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
            process(_body(record))

        return partial_batch(records, process_record)
    return process(event)
