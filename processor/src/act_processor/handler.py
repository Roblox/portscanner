"""EventBridge-scheduled full finding reconciliation and handoff repair."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import boto3
import psycopg
from act_parser.config import ConfigurationError, database_dsn
from act_parser.database import Repository
from act_parser.handoff import HandoffPublisher


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    invocation_key = event.get("id")
    if not isinstance(invocation_key, str) or not invocation_key:
        raise ValueError("scheduled event must contain a stable id")
    finding_bucket = os.getenv("FINDING_BUCKET")
    if not finding_bucket:
        raise ConfigurationError("FINDING_BUCKET is required")

    s3 = boto3.client("s3")
    with psycopg.connect(database_dsn()) as connection:
        repository = Repository(connection)
        result = repository.reconcile_all(
            invocation_key,
            finding_bucket=finding_bucket,
        )

        publisher = HandoffPublisher(s3, repository)
        page_size = min(1000, int(os.getenv("HANDOFF_PAGE_SIZE", "1000")))
        published = publisher.publish_all(keys=None, page_size=page_size)

    return {
        "run_id": invocation_key,
        "duplicate": result.duplicate,
        "findings_examined": result.findings_examined,
        "objects_published": published,
    }
