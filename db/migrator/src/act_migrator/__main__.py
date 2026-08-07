"""Command-line entrypoint for controlled migration runs."""

from __future__ import annotations

import argparse
import hmac
import os
import re
import sys

import boto3
import psycopg

from .config import database_settings_from_environment
from .credentials import DEFAULT_APPLICATION_USERNAME, provision_application_credentials
from .handler import default_migrations_path, target_supports_credential_provisioning
from .migrator import Migrator, discover_migrations, migration_set_checksum


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate the ACT PostgreSQL schema")
    parser.add_argument(
        "--migrations",
        default=str(default_migrations_path()),
        help="directory containing paired migration SQL files",
    )
    parser.add_argument("--direction", choices=("up", "down"), default="up")
    parser.add_argument("--target")
    parser.add_argument("--steps", type=int)
    parser.add_argument(
        "--migration-checksum",
        default=os.getenv("MIGRATION_CHECKSUM"),
        help="expected SHA-256 of the ordered migration artifact set",
    )
    arguments = parser.parse_args()

    if (
        not isinstance(arguments.migration_checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", arguments.migration_checksum) is None
    ):
        parser.error("--migration-checksum is required and must be a lowercase SHA-256 value")
    actual_checksum = migration_set_checksum(arguments.migrations)
    if not hmac.compare_digest(actual_checksum, arguments.migration_checksum):
        parser.error("--migration-checksum does not match the migration artifact set")

    migrations = discover_migrations(arguments.migrations)
    secrets_client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION"))
    database = database_settings_from_environment(client=secrets_client)
    with psycopg.connect(database.dsn) as connection:
        migrator = Migrator(connection, migrations)
        if arguments.direction == "up":
            with migrator.advisory_lock():
                changed = migrator.up(target=arguments.target)
                if target_supports_credential_provisioning(arguments.target):
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
                else:
                    sys.stdout.write(
                        "credentials skipped: target precedes application CONNECT migration\n"
                    )
        else:
            if arguments.target is None and arguments.steps is None:
                parser.error("--direction down requires --target or --steps")
            changed = migrator.down(
                target=arguments.target,
                steps=None if arguments.target is not None else arguments.steps,
            )

    for version in changed:
        sys.stdout.write(f"{arguments.direction} {version}\n")


if __name__ == "__main__":
    main()
