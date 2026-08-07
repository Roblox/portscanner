"""AWS Lambda entrypoint for checksum-triggered migration invocations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import boto3
import psycopg

from .config import database_settings_from_environment
from .credentials import DEFAULT_APPLICATION_USERNAME, provision_application_credentials
from .migrator import MigrationError, Migrator, discover_migrations


def default_migrations_path() -> Path:
    configured = os.getenv("MIGRATIONS_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "migrations"


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    direction = event.get("direction", "up")
    target = event.get("target")
    if direction not in {"up", "down"}:
        raise MigrationError("direction must be up or down")
    migrations = discover_migrations(default_migrations_path())
    secrets_client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION"))
    database = database_settings_from_environment(client=secrets_client)
    credentials_repaired = False

    with psycopg.connect(database.dsn) as connection:
        migrator = Migrator(connection, migrations)
        if direction == "up":
            changed = migrator.up(target=target)
            provision_application_credentials(
                connection,
                secrets_client,
                database=database,
                application_secret_id=os.getenv("DB_APPLICATION_SECRET_ID", ""),
                application_username=os.getenv(
                    "DB_APPLICATION_USERNAME",
                    DEFAULT_APPLICATION_USERNAME,
                ),
            )
            credentials_repaired = True
        elif direction == "down":
            if target is None and "steps" not in event:
                raise MigrationError("down invocation must explicitly provide target or steps")
            changed = migrator.down(
                target=target,
                steps=None if target is not None else int(event["steps"]),
            )

    return {
        "direction": direction,
        "changed_versions": changed,
        "latest_version": migrations[-1].version,
        "credentials_repaired": credentials_repaired,
    }
