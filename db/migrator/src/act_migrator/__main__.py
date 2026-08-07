"""Command-line entrypoint for controlled migration runs."""

from __future__ import annotations

import argparse
import os
import sys

import boto3
import psycopg

from .config import database_settings_from_environment
from .credentials import DEFAULT_APPLICATION_USERNAME, provision_application_credentials
from .handler import default_migrations_path
from .migrator import Migrator, discover_migrations


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
    arguments = parser.parse_args()

    migrations = discover_migrations(arguments.migrations)
    secrets_client = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION"))
    database = database_settings_from_environment(client=secrets_client)
    with psycopg.connect(database.dsn) as connection:
        migrator = Migrator(connection, migrations)
        if arguments.direction == "up":
            changed = migrator.up(target=arguments.target)
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
