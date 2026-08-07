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


def _has_direct_connect(connection: Any, role_name: str) -> bool:
    return bool(
        connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_database AS database
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(database.datacl, acldefault('d', database.datdba))
                ) AS privilege
                JOIN pg_catalog.pg_roles AS role
                  ON role.oid = privilege.grantee
                WHERE database.datname = current_database()
                  AND role.rolname = %s
                  AND privilege.privilege_type = 'CONNECT'
            )
            """,
            (role_name,),
        ).fetchone()[0]
    )


def _assert_direct_rollback_revokes_managed_connect(
    connection: Any,
    migrator: Migrator,
    *,
    public_connect_baseline: bool,
) -> None:
    assert migrator.down(target="000003", steps=None) == ["000004"]
    assert not _has_direct_connect(connection, "act_runtime_test")
    assert (
        connection.execute(
            """
            SELECT has_database_privilege(
                'act_runtime_test',
                current_database(),
                'CONNECT'
            )
            """
        ).fetchone()[0]
        is public_connect_baseline
    )


def test_fresh_up_down_and_repeat_execution() -> None:
    migrations_path = Path(__file__).resolve().parents[2] / "migrations"
    migrations = discover_migrations(migrations_path)

    with psycopg.connect(DATABASE_URL) as connection:
        migrator = Migrator(connection, migrations)
        migrator.down(target="000000", steps=None)

        public_connect_baseline = connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba)))
                WHERE grantee = 0
                  AND privilege_type = 'CONNECT'
            )
            FROM pg_catalog.pg_database AS database
            WHERE database.datname = current_database()
            """
        ).fetchone()[0]

        assert migrator.up() == ["000001", "000002", "000003", "000004", "000005"]
        assert migrator.up() == []
        rows = connection.execute(
            "SELECT version, checksum FROM public.schema_migrations ORDER BY version"
        ).fetchall()
        assert [row[0] for row in rows] == [
            "000001",
            "000002",
            "000003",
            "000004",
            "000005",
        ]
        assert [row[1].strip() for row in rows] == [migration.checksum for migration in migrations]
        assert (
            connection.execute("SELECT to_regclass('act.current_findings')").fetchone()[0]
            == "act.current_findings"
        )
        connection.execute(
            """
            UPDATE act.detection_rules
            SET severity = 'informational'
            WHERE rule_key = 'new-or-reopened-exposure'
            """
        )
        assert connection.execute(
            """
            SELECT severity
            FROM act.detection_rules
            WHERE rule_key = 'new-or-reopened-exposure'
            """
        ).fetchone() == ("informational",)
        connection.execute(
            """
            UPDATE act.detection_rules
            SET severity = 'low'
            WHERE rule_key = 'new-or-reopened-exposure'
            """
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
            connection.execute("SELECT act.revoke_application_role('act_runtime_test')")
            assert not connection.execute(
                """
                SELECT has_database_privilege(
                    'act_runtime_test',
                    current_database(),
                    'CONNECT'
                )
                """
            ).fetchone()[0]
            connection.execute("SELECT act.grant_application_role('act_runtime_test')")
            assert connection.execute(
                """
                SELECT has_database_privilege(
                    'act_runtime_test',
                    current_database(),
                    'CONNECT'
                )
                """
            ).fetchone()[0]

            assert migrator.down(target="000004", steps=None) == ["000005"]
            assert _has_direct_connect(connection, "act_runtime_test")
            assert connection.execute(
                """
                SELECT has_database_privilege(
                    'act_runtime_test',
                    current_database(),
                    'CONNECT'
                )
                """
            ).fetchone()[0]

            _assert_direct_rollback_revokes_managed_connect(
                connection,
                migrator,
                public_connect_baseline=public_connect_baseline,
            )

            assert migrator.up() == ["000004", "000005"]
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
                password_factory=lambda: pytest.fail("password must not be regenerated"),
            )
        finally:
            connection.execute("SELECT act.revoke_application_role('act_runtime_test')")

        assert migrator.down(target="000000", steps=None) == [
            "000005",
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
