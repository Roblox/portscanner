"""AWS Lambda entrypoint for checksum-triggered migration invocations."""

from __future__ import annotations

import hmac
import os
import re
from pathlib import Path
from typing import Any

import boto3
import psycopg

from .config import database_settings_from_environment
from .credentials import DEFAULT_APPLICATION_USERNAME, provision_application_credentials
from .migrator import MigrationError, Migrator, discover_migrations, migration_set_checksum

APPLICATION_CONNECT_MIGRATION_VERSION = "000001"


def default_migrations_path() -> Path:
    configured = os.getenv("MIGRATIONS_PATH")
    if configured:
        return Path(configured)
    module_path = Path(__file__).resolve()
    packaged = module_path.parent / "migrations"
    if packaged.is_dir():
        return packaged
    repository = module_path.parents[3] / "migrations"
    if repository.is_dir():
        return repository
    raise MigrationError(
        "migration SQL is missing; reinstall portscanner-migrator or set MIGRATIONS_PATH"
    )


def target_supports_credential_provisioning(target: str | None) -> bool:
    """The fresh-install baseline includes explicit database CONNECT grants."""
    return target is None or target >= APPLICATION_CONNECT_MIGRATION_VERSION


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    direction = event.get("direction", "up")
    target = event.get("target")
    if direction not in {"up", "down"}:
        raise MigrationError("direction must be up or down")
    migrations_path = default_migrations_path()
    expected_checksum = event.get("migration_checksum")
    if (
        not isinstance(expected_checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_checksum) is None
    ):
        raise MigrationError("migration_checksum must be a lowercase SHA-256 value")
    actual_checksum = migration_set_checksum(migrations_path)
    if not hmac.compare_digest(actual_checksum, expected_checksum):
        raise MigrationError("migration artifact checksum does not match the requested checksum")
    migrations = discover_migrations(migrations_path)
    secrets_client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION"))
    database = database_settings_from_environment(client=secrets_client)
    credentials_repaired = False
    credentials_status = "not_applicable"

    with psycopg.connect(database.dsn) as connection:
        migrator = Migrator(connection, migrations)
        if direction == "up":
            with migrator.advisory_lock():
                changed = migrator.up(target=target)
                if target_supports_credential_provisioning(target):
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
                    credentials_status = "repaired"
                else:
                    credentials_status = "skipped_target_before_application_connect"
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
        "credentials_status": credentials_status,
        "migration_checksum": actual_checksum,
    }
