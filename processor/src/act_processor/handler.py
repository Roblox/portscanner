"""Scheduled reconciliation and narrow managed-canary verification."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import boto3
import psycopg
from act_parser.config import ConfigurationError, database_dsn
from act_parser.database import Repository
from act_parser.handoff import HandoffPublisher

_MAX_PORT = 65_535
_MAX_HANDOFF_PAGE_SIZE = 1000


@dataclass(frozen=True, slots=True)
class _CanaryScope:
    account_id: str
    region: str
    network_interface_id: str
    private_ip: str
    public_ip: str
    tag_key: str
    tag_value: str
    port: int


def _enabled(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    if raw.lower() not in {"true", "false"}:
        raise ConfigurationError(f"{name} must be true or false")
    return raw.lower() == "true"


def _canary_scope() -> _CanaryScope:
    names = {
        "account_id": "MANAGED_CANARY_ACCOUNT_ID",
        "region": "MANAGED_CANARY_REGION",
        "network_interface_id": "MANAGED_CANARY_ENI_ID",
        "private_ip": "MANAGED_CANARY_PRIVATE_IP",
        "public_ip": "MANAGED_CANARY_PUBLIC_IP",
        "tag_key": "MANAGED_CANARY_TAG_KEY",
        "tag_value": "MANAGED_CANARY_TAG_VALUE",
        "port": "MANAGED_CANARY_TCP_PORT",
    }
    values = {field: (os.getenv(name) or "").strip() for field, name in names.items()}
    missing = [names[field] for field, value in values.items() if not value]
    if missing:
        raise ConfigurationError(
            f"managed canary status configuration is incomplete: {', '.join(sorted(missing))}"
        )
    try:
        port = int(values["port"])
    except ValueError as error:
        raise ConfigurationError("MANAGED_CANARY_TCP_PORT must be an integer") from error
    if not 1 <= port <= _MAX_PORT:
        raise ConfigurationError("MANAGED_CANARY_TCP_PORT must be within 1..65535")
    return _CanaryScope(
        account_id=values["account_id"],
        region=values["region"],
        network_interface_id=values["network_interface_id"],
        private_ip=values["private_ip"],
        public_ip=values["public_ip"],
        tag_key=values["tag_key"],
        tag_value=values["tag_value"],
        port=port,
    )


def _count(row: Mapping[str, Any], name: str) -> int:
    value = row.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError("managed canary status query returned invalid counts")
    return value


def _managed_canary_status(connection: Any, scope: _CanaryScope) -> dict[str, Any]:
    row = connection.execute(
        """
        WITH exact_targets AS (
            SELECT target_id
            FROM act.targets
            WHERE provider = 'aws'
              AND status = 'active'
              AND provider_scope_id = %s
              AND location = %s
              AND context ->> 'network_interface_id' = %s
              AND context ->> 'private_ip' = %s
              AND context ->> 'public_ip' = %s
              AND context -> 'tags' ->> %s = %s
        )
        SELECT
            (SELECT count(*) FROM exact_targets) AS target_count,
            (
                SELECT count(*)
                FROM act.target_events AS event
                WHERE event.target_id IN (SELECT target_id FROM exact_targets)
                  AND event.accepted
            ) AS event_count,
            (
                SELECT count(*)
                FROM act.scan_attempts AS attempt
                WHERE attempt.target_id IN (SELECT target_id FROM exact_targets)
            ) AS attempt_count,
            (
                SELECT count(*)
                FROM act.scan_attempts AS attempt
                WHERE attempt.target_id IN (SELECT target_id FROM exact_targets)
                  AND attempt.outcome = 'complete'
                  AND attempt.state_eligible
                  AND attempt.profile = 'targeted-tcp'
                  AND EXISTS (
                      SELECT 1
                      FROM act.scan_attempt_coverage AS coverage
                      WHERE coverage.attempt_id = attempt.attempt_id
                        AND coverage.protocol = 'tcp'
                        AND coverage.complete
                        AND coverage.port_from = %s
                        AND coverage.port_to = %s
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM act.scan_attempt_coverage AS coverage
                      WHERE coverage.attempt_id = attempt.attempt_id
                        AND (
                            coverage.protocol IS DISTINCT FROM 'tcp'
                            OR coverage.complete IS DISTINCT FROM TRUE
                            OR coverage.port_from IS DISTINCT FROM %s
                            OR coverage.port_to IS DISTINCT FROM %s
                        )
                  )
            ) AS complete_coverage_count,
            (
                SELECT count(*)
                FROM act.exposure_state AS exposure
                WHERE exposure.target_id IN (SELECT target_id FROM exact_targets)
                  AND exposure.protocol = 'tcp'
                  AND exposure.port = %s
                  AND exposure.state = 'open'
            ) AS open_exposure_count,
            (
                SELECT count(*)
                FROM act.findings AS finding
                WHERE finding.target_id IN (SELECT target_id FROM exact_targets)
                  AND finding.protocol = 'tcp'
                  AND finding.port = %s
                  AND finding.status = 'open'
                  AND finding.severity = 'low'
            ) AS low_finding_count,
            (
                SELECT count(*)
                FROM act.findings AS finding
                WHERE finding.target_id IN (SELECT target_id FROM exact_targets)
                  AND finding.status = 'open'
                  AND finding.severity IN ('high', 'critical')
            ) AS unexpected_high_finding_count
        """,
        (
            scope.account_id,
            scope.region,
            scope.network_interface_id,
            scope.private_ip,
            scope.public_ip,
            scope.tag_key,
            scope.tag_value,
            scope.port,
            scope.port,
            scope.port,
            scope.port,
            scope.port,
            scope.port,
        ),
    ).fetchone()
    if not isinstance(row, Mapping):
        raise RuntimeError("managed canary status query returned no row")
    counts = {
        name: _count(row, name)
        for name in (
            "target_count",
            "event_count",
            "attempt_count",
            "complete_coverage_count",
            "open_exposure_count",
            "low_finding_count",
            "unexpected_high_finding_count",
        )
    }
    ready = (
        counts["target_count"] == 1
        and counts["event_count"] == 1
        and counts["attempt_count"] == 1
        and counts["complete_coverage_count"] == 1
        and counts["open_exposure_count"] == 1
        and counts["low_finding_count"] == 1
        and counts["unexpected_high_finding_count"] == 0
    )
    return {
        "operation": "managed-canary-status",
        "status": "ready" if ready else "pending",
        "ready": ready,
        **counts,
    }


def _scheduled_reconciliation(event: Mapping[str, Any]) -> dict[str, Any]:
    invocation_key = event.get("id")
    if not isinstance(invocation_key, str) or not invocation_key:
        raise ValueError("scheduled event must contain a stable id")
    finding_export_enabled = _enabled("FINDING_EXPORT_ENABLED", default=True)
    finding_bucket = os.getenv("FINDING_BUCKET")
    if finding_export_enabled and not finding_bucket:
        raise ConfigurationError("FINDING_BUCKET is required")

    with psycopg.connect(database_dsn()) as connection:
        repository = Repository(connection)
        result = repository.reconcile_all(
            invocation_key,
            finding_bucket=finding_bucket,
            queue_finding_handoffs=finding_export_enabled,
        )
        published = 0
        if finding_export_enabled:
            page_size = int(os.getenv("HANDOFF_PAGE_SIZE", "1000"))
            if not 1 <= page_size <= _MAX_HANDOFF_PAGE_SIZE:
                raise ConfigurationError("HANDOFF_PAGE_SIZE must be between 1 and 1000")
            published = HandoffPublisher(boto3.client("s3"), repository).publish_all(
                keys=None,
                page_size=page_size,
            )

    return {
        "run_id": invocation_key,
        "duplicate": result.duplicate,
        "findings_examined": result.findings_examined,
        "objects_published": published,
    }


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    if event.get("operation") == "managed-canary-status":
        scope = _canary_scope()
        with psycopg.connect(database_dsn()) as connection:
            return _managed_canary_status(connection, scope)
    return _scheduled_reconciliation(event)
