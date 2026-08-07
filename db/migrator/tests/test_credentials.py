from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import pytest
from act_migrator.config import DatabaseSettings
from act_migrator.credentials import provision_application_credentials
from act_migrator.migrator import MigrationError
from botocore.exceptions import ClientError
from psycopg import sql


class _Result:
    def __init__(self, row: object | None) -> None:
        self.row = row

    def fetchone(self) -> object | None:
        return self.row


class _Connection:
    def __init__(self, *, role_exists: bool) -> None:
        self.role_exists = role_exists
        self.executions: list[tuple[Any, object | None]] = []
        self.transactions = 0

    @contextmanager
    def transaction(self) -> Any:
        self.transactions += 1
        yield

    def execute(self, statement: Any, parameters: object | None = None) -> _Result:
        self.executions.append((statement, parameters))
        if statement == "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s":
            return _Result((1,) if self.role_exists else None)
        return _Result(None)


class _Secrets:
    def __init__(self, value: dict[str, Any] | None) -> None:
        self.value = value
        self.puts: list[dict[str, Any]] = []

    def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["SecretId"] == SECRET_ID
        if self.value is None:
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}},
                "GetSecretValue",
            )
        return {"SecretString": json.dumps(self.value)}

    def put_secret_value(self, **kwargs: Any) -> None:
        self.puts.append(kwargs)
        self.value = json.loads(kwargs["SecretString"])


DATABASE = DatabaseSettings(
    dsn="postgresql://unused",
    host="database.example",
    port=5432,
    dbname="portscanner",
    sslmode="verify-full",
)
PASSWORD = "generated-application-password-value-000000000000"
SECRET_ID = "application-secret"


def test_empty_secret_creates_login_role_and_stores_generated_password() -> None:
    connection = _Connection(role_exists=False)
    secrets = _Secrets(None)

    result = provision_application_credentials(
        connection,  # type: ignore[arg-type]
        secrets,
        database=DATABASE,
        application_secret_id=SECRET_ID,
        application_username="runtime-role",
        password_factory=lambda: PASSWORD,
    )

    assert result.role_created
    assert result.secret_updated
    assert connection.transactions == 1
    assert any(
        isinstance(statement, sql.Composed)
        and any(isinstance(part, sql.Identifier) for part in statement)
        for statement, _parameters in connection.executions
    )
    assert connection.executions[-1] == (
        "SELECT act.grant_application_role(%s::NAME)",
        ("runtime-role",),
    )
    assert secrets.value == {
        "host": "database.example",
        "port": 5432,
        "dbname": "portscanner",
        "username": "runtime-role",
        "password": PASSWORD,
        "sslmode": "verify-full",
    }
    assert secrets.puts[0]["SecretId"] == SECRET_ID


def test_existing_secret_repairs_role_without_generating_or_rewriting() -> None:
    stored = {
        "host": "database.example",
        "port": 5432,
        "dbname": "portscanner",
        "username": "runtime-role",
        "password": PASSWORD,
        "sslmode": "verify-full",
    }
    connection = _Connection(role_exists=True)
    secrets = _Secrets(stored)

    result = provision_application_credentials(
        connection,  # type: ignore[arg-type]
        secrets,
        database=DATABASE,
        application_secret_id=SECRET_ID,
        application_username="runtime-role",
        password_factory=lambda: pytest.fail("password must not be regenerated"),
    )

    assert not result.role_created
    assert not result.secret_updated
    assert secrets.puts == []
    alter_statements = [
        statement
        for statement, parameters in connection.executions
        if isinstance(statement, sql.Composed)
        and parameters is None
        and any(isinstance(part, sql.Literal) for part in statement)
    ]
    assert len(alter_statements) == 1


def test_existing_secret_without_password_is_not_silently_replaced() -> None:
    with pytest.raises(MigrationError, match="no password"):
        provision_application_credentials(
            _Connection(role_exists=True),  # type: ignore[arg-type]
            _Secrets({"username": "runtime-role"}),
            database=DATABASE,
            application_secret_id=SECRET_ID,
            application_username="runtime-role",
            password_factory=lambda: pytest.fail("password must not be generated"),
        )
