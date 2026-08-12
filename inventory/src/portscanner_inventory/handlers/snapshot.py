"""Lambda handler for complete-scope snapshot reconciliation."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Mapping
from datetime import datetime
from ipaddress import AddressValueError, IPv4Address
from typing import Any

from portscanner_inventory.aws.config_snapshot import ConfigSnapshotBackend
from portscanner_inventory.aws.ec2_snapshot import Ec2SnapshotBackend
from portscanner_inventory.aws.ownership import OwnershipValidator
from portscanner_inventory.aws.session import AwsClientFactory
from portscanner_inventory.base import (
    OwnershipVerdict,
    SnapshotScope,
    partial_batch,
    structured_log,
    utc_now,
)
from portscanner_inventory.config import Settings
from portscanner_inventory.events import snapshot_source
from portscanner_inventory.state import DynamoStateStore, ReconcileAction

LOGGER = logging.getLogger(__name__)


def reconcile_snapshot(
    backend: Any,
    state: Any,
    ownership: Any,
    *,
    now: datetime,
    target_public_ipv4: str | None = None,
    require_exact_target: bool = False,
) -> dict[str, Any]:
    """Apply observed targets, then remove only directly revalidated absences."""

    batch = backend.collect()
    if require_exact_target and not batch.complete:
        raise ValueError("canary snapshot requires a complete inventory response")
    source = snapshot_source(batch.scope, now)
    counts = {
        action.value: 0 for action in ReconcileAction if action is not ReconcileAction.REVALIDATE
    }
    selected = tuple(
        target
        for target in batch.targets
        if target_public_ipv4 is None or target.public_ip == target_public_ipv4
    )
    if require_exact_target and len(selected) != 1:
        raise ValueError("canary snapshot must resolve target_public_ipv4 to exactly one target")

    observed_ids: set[str] = set()
    revalidated = 0
    for raw_target in selected:
        target = (
            raw_target if raw_target.observed_at is not None else raw_target.with_observation(now)
        )
        observed_ids.add(target.target_id)
        target_source = snapshot_source(
            batch.scope,
            now,
            observed_at=target.observed_at,
        )
        result = state.reconcile(target, source=target_source, now=now)
        if result.action is ReconcileAction.REVALIDATE and result.state is not None:
            revalidated += 1
            revalidation = ownership.validate(
                result.state.target_id,
                result.state.generation,
            )
            if revalidation.verdict in {
                OwnershipVerdict.INACTIVE,
                OwnershipVerdict.MOVED,
            }:
                result = state.remove(result.state, source=source, now=now)
            elif (
                revalidation.verdict is OwnershipVerdict.STALE
                and revalidation.current is not None
                and revalidation.reason == "policy-or-lifecycle"
            ):
                live_target = revalidation.current.with_observation(now)
                live_source = snapshot_source(batch.scope, now, observed_at=now)
                result = state.reconcile(live_target, source=live_source, now=now)
                if result.state is not None and result.state.signature == target.state_signature:
                    state.confirm_config_versions(result.state, target, now=now)
            elif revalidation.verdict is OwnershipVerdict.ACTIVE:
                result = state.confirm_config_versions(result.state, target, now=now)
            else:
                counts[ReconcileAction.NOOP.value] += 1
                continue
        counts[result.action.value] += 1

    if batch.complete and target_public_ipv4 is None:
        for current in state.list_current(batch.scope):
            if current.target_id in observed_ids:
                continue
            revalidated += 1
            check = ownership.validate(current.target_id, current.generation)
            if check.verdict in {OwnershipVerdict.INACTIVE, OwnershipVerdict.MOVED}:
                result = state.remove(current, source=source, now=now)
                counts[result.action.value] += 1
            elif (
                check.verdict is OwnershipVerdict.STALE
                and check.current is not None
                and check.reason == "policy-or-lifecycle"
            ):
                live_target = check.current.with_observation(now)
                live_source = snapshot_source(batch.scope, now, observed_at=now)
                result = state.reconcile(live_target, source=live_source, now=now)
                counts[result.action.value] += 1

    summary = {
        "completion": batch.completion.value,
        "targets": len(selected),
        "pages": batch.pages,
        "revalidated": revalidated,
        **counts,
    }
    structured_log(
        LOGGER,
        "snapshot",
        completion=batch.completion.value,
        targets=len(selected),
        pages=batch.pages,
        events=counts["added"] + counts["changed"] + counts["removed"],
    )
    return summary


def _requested_target_public_ipv4(request: Mapping[str, Any]) -> str | None:
    value = request.get("target_public_ipv4")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("target_public_ipv4 must be a canonical public IPv4 address")
    try:
        address = IPv4Address(value)
    except AddressValueError as exc:
        raise ValueError("target_public_ipv4 must be a canonical public IPv4 address") from exc
    if str(address) != value or not address.is_global:
        raise ValueError("target_public_ipv4 must be a canonical public IPv4 address")
    return str(address)


def _requested_account_id(request: Mapping[str, Any], settings: Settings) -> str:
    value = request.get("account_id", settings.account_id)
    if not isinstance(value, str) or value not in settings.authorized_account_ids:
        raise ValueError("account_id is outside the configured authorized account scope")
    return value


def _requested_region(
    request: Mapping[str, Any],
    settings: Settings,
    *,
    field: str = "region",
) -> str | None:
    value = request.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or value not in settings.regions:
        raise ValueError(f"{field} is outside the configured snapshot Region scope")
    return value


class _Runtime:
    def __init__(self, settings: Settings) -> None:
        import boto3

        settings.validate_snapshot()
        self.settings = settings
        self.session = boto3.Session()
        self.state = DynamoStateStore(
            self.session.client("dynamodb"),
            settings.state_table,
            outbox_ttl_seconds=settings.outbox_ttl_seconds,
        )
        self.factory = AwsClientFactory(
            self.session,
            role_arn_template=settings.discovery_role_arn_template,
            external_id=settings.external_id,
            local_account_id=settings.account_id,
        )
        self.ownership = OwnershipValidator(
            self.state,
            self.factory,
            allowed_tag_keys=settings.allowed_tag_keys,
        )

    def process(self, request: Mapping[str, Any]) -> list[dict[str, Any]]:
        now = utc_now()
        target_public_ipv4 = _requested_target_public_ipv4(request)
        account_id = _requested_account_id(request, self.settings)
        requested_region = _requested_region(request, self.settings)
        if self.settings.canary_mode and (
            target_public_ipv4 is None or "account_id" not in request or requested_region is None
        ):
            raise ValueError("canary snapshot requires account_id, region, and target_public_ipv4")
        backend: ConfigSnapshotBackend | Ec2SnapshotBackend
        if self.settings.snapshot_backend == "config":
            client_region = os.environ.get("AWS_REGION") or "us-east-1"
            legacy_target_region = _requested_region(
                request,
                self.settings,
                field="target_region",
            )
            if (
                requested_region is not None
                and legacy_target_region is not None
                and requested_region != legacy_target_region
            ):
                raise ValueError("region and target_region must identify the same target Region")
            target_region = requested_region or legacy_target_region
            client = self.session.client("config", region_name=client_region)
            scope = SnapshotScope(
                source="aws-config",
                name=self.settings.config_aggregator_name,
                account_id=account_id,
                region=target_region,
            )
            backend = ConfigSnapshotBackend(
                client,
                aggregator_name=self.settings.config_aggregator_name or "",
                scope=scope,
                allowed_tag_keys=self.settings.allowed_tag_keys,
            )
            return [
                reconcile_snapshot(
                    backend,
                    self.state,
                    self.ownership,
                    now=now,
                    target_public_ipv4=target_public_ipv4,
                    require_exact_target=self.settings.canary_mode,
                )
            ]

        regions = (requested_region,) if requested_region else self.settings.regions
        summaries = []
        for region in regions:
            client = self.factory.client("ec2", account_id=account_id, region=region)
            backend = Ec2SnapshotBackend(
                client,
                account_id=account_id,
                region=region,
                allowed_tag_keys=self.settings.allowed_tag_keys,
            )
            summaries.append(
                reconcile_snapshot(
                    backend,
                    self.state,
                    self.ownership,
                    now=now,
                    target_public_ipv4=target_public_ipv4,
                    require_exact_target=self.settings.canary_mode,
                )
            )
        return summaries


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
                raise ValueError("snapshot message body must be an object")
            process(body)

        return partial_batch(records, process_record)
    return process(event)
