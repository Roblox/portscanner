from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import psycopg
import pytest
from act_migrator.config import DatabaseSettings
from act_migrator.credentials import provision_application_credentials
from act_migrator.migrator import Migrator, discover_migrations
from botocore.exceptions import ClientError

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
APPLICATION_SECRET_ID = "application-secret"
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="TEST_DATABASE_URL is required for PostgreSQL integration tests",
)


def test_fresh_up_down_and_repeat_execution() -> None:
    migrations_path = Path(__file__).resolve().parents[2] / "migrations"
    migrations = discover_migrations(migrations_path)

    with psycopg.connect(DATABASE_URL) as connection:
        migrator = Migrator(connection, migrations)
        migrator.down(target="000000", steps=None)

        assert migrator.up() == ["000001", "000002", "000003", "000004"]
        assert migrator.up() == []
        rows = connection.execute(
            "SELECT version, checksum FROM public.schema_migrations ORDER BY version"
        ).fetchall()
        assert [row[0] for row in rows] == ["000001", "000002", "000003", "000004"]
        assert [row[1].strip() for row in rows] == [migration.checksum for migration in migrations]
        assert (
            connection.execute("SELECT to_regclass('act.current_findings')").fetchone()[0]
            == "act.current_findings"
        )

        existing_role = connection.execute(
            "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'act_runtime_test'"
        ).fetchone()
        if existing_role is not None:
            connection.execute("DROP OWNED BY act_runtime_test")
            connection.execute("DROP ROLE act_runtime_test")

        class Secrets:
            value: dict[str, Any] | None = None

            def get_secret_value(self, **_kwargs: Any) -> dict[str, Any]:
                if self.value is None:
                    raise ClientError(
                        {"Error": {"Code": "ResourceNotFoundException"}},
                        "GetSecretValue",
                    )
                return {"SecretString": json.dumps(self.value)}

            def put_secret_value(self, **kwargs: Any) -> None:
                self.value = json.loads(kwargs["SecretString"])

        secrets = Secrets()
        provision_application_credentials(
            connection,
            secrets,
            database=DatabaseSettings(
                dsn=DATABASE_URL or "",
                host="database.example",
                port=5432,
                dbname="portscanner",
                sslmode="require",
            ),
            application_secret_id=APPLICATION_SECRET_ID,
            application_username="act_runtime_test",
            password_factory=lambda: "integration-password-value-000000000000000000",
        )
        try:
            role = connection.execute(
                """
                SELECT
                    rolcanlogin,
                    rolsuper,
                    rolcreatedb,
                    rolcreaterole,
                    rolreplication,
                    rolbypassrls
                FROM pg_catalog.pg_roles
                WHERE rolname = 'act_runtime_test'
                """
            ).fetchone()
            assert role == (True, False, False, False, False, False)
            update_columns = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT column_name
                    FROM information_schema.column_privileges
                    WHERE grantee = 'act_runtime_test'
                      AND table_schema = 'act'
                      AND table_name = 'targets'
                      AND privilege_type = 'UPDATE'
                    """
                ).fetchall()
            }
            assert "current_generation" in update_columns
            assert "provider" not in update_columns
            privileges = connection.execute(
                """
                SELECT
                    has_database_privilege(
                        'act_runtime_test',
                        current_database(),
                        'CONNECT'
                    ),
                    has_schema_privilege('act_runtime_test', 'act', 'USAGE'),
                    has_schema_privilege('act_runtime_test', 'act', 'CREATE'),
                    has_table_privilege('act_runtime_test', 'act.target_events', 'INSERT'),
                    has_table_privilege('act_runtime_test', 'act.scan_attempts', 'INSERT'),
                    has_table_privilege('act_runtime_test', 'act.observations', 'INSERT'),
                    has_table_privilege(
                        'act_runtime_test',
                        'act.reconciliation_runs',
                        'INSERT'
                    ),
                    has_table_privilege(
                        'act_runtime_test',
                        'act.current_findings',
                        'SELECT'
                    ),
                    has_table_privilege('act_runtime_test', 'act.targets', 'DELETE'),
                    has_table_privilege(
                        'act_runtime_test',
                        'act.detection_rules',
                        'UPDATE'
                    )
                """
            ).fetchone()
            assert privileges == (
                True,
                True,
                False,
                True,
                True,
                True,
                True,
                True,
                False,
                False,
            )
        finally:
            connection.execute("SELECT act.revoke_application_role('act_runtime_test')")

        assert migrator.down(target="000000", steps=None) == [
            "000004",
            "000003",
            "000002",
            "000001",
        ]
        assert connection.execute("SELECT to_regnamespace('act')").fetchone()[0] is None
        assert connection.execute(
            "SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = 'act_runtime_test'"
        ).fetchone() == (True,)
        connection.execute("DROP OWNED BY act_runtime_test")
        connection.execute("DROP ROLE act_runtime_test")
        assert migrator.down(target="000000", steps=None) == []
