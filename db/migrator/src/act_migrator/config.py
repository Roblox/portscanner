"""Secret loading and TLS-enforced PostgreSQL connection settings."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import boto3
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from .migrator import MigrationError

_TLS_MODES = {"require", "verify-ca", "verify-full"}
_MAX_PORT = 65535


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    dsn: str
    host: str
    port: int
    dbname: str
    sslmode: str


def _required_text(value: object, source: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise MigrationError(f"{source} {field} must be a non-empty string")
    return value


def _validated_port(value: object, source: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise MigrationError(f"{source} port must be an integer")
    try:
        port = int(value)
    except ValueError as error:
        raise MigrationError(f"{source} port must be an integer") from error
    if not 1 <= port <= _MAX_PORT:
        raise MigrationError(f"{source} port must be between 1 and 65535")
    return port


def require_tls(dsn: str, *, allow_insecure_test_database: bool = False) -> str:
    parameters = conninfo_to_dict(dsn)
    sslmode = parameters.get("sslmode")
    if sslmode not in _TLS_MODES and not allow_insecure_test_database:
        raise MigrationError(
            "database connection must set sslmode=require, verify-ca, or verify-full"
        )
    return dsn


def _secret_payload(response: Mapping[str, Any]) -> Mapping[str, Any]:
    if "SecretString" in response:
        encoded = response["SecretString"]
    elif "SecretBinary" in response:
        raw = response["SecretBinary"]
        if isinstance(raw, str):
            raw = base64.b64decode(raw)
        encoded = bytes(raw).decode("utf-8")
    else:
        raise MigrationError("database secret has no value")

    try:
        value = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise MigrationError("database secret is not valid JSON") from error
    if not isinstance(value, dict):
        raise MigrationError("database secret must contain a JSON object")
    return value


def dsn_from_secret(
    secret_id: str,
    region: str | None = None,
    *,
    client: Any | None = None,
    database_name: str | None = None,
) -> str:
    return database_settings_from_secret(
        secret_id,
        region,
        client=client,
        database_name=database_name,
    ).dsn


def database_settings_from_secret(
    secret_id: str,
    region: str | None = None,
    *,
    client: Any | None = None,
    database_name: str | None = None,
) -> DatabaseSettings:
    secrets = client or boto3.client("secretsmanager", region_name=region)
    response = secrets.get_secret_value(SecretId=secret_id)
    secret = _secret_payload(response)

    raw_user = secret.get("username") or secret.get("user")
    raw_database = (
        secret.get("dbname") or secret.get("database") or database_name or os.getenv("DB_NAME")
    )
    required = {
        "host": secret.get("host"),
        "user": raw_user,
        "password": secret.get("password"),
        "dbname": raw_database,
    }
    missing = [key for key, value in required.items() if value in (None, "")]
    if missing:
        raise MigrationError(
            f"database secret is missing required fields: {', '.join(sorted(missing))}"
        )

    host = _required_text(required["host"], "database secret", "host")
    user = _required_text(required["user"], "database secret", "username")
    password = _required_text(required["password"], "database secret", "password")
    database = _required_text(required["dbname"], "database secret", "database name")
    port = _validated_port(secret.get("port", 5432), "database secret")
    sslmode = _required_text(
        secret.get("sslmode") or os.getenv("DB_SSLMODE", "require"),
        "database secret",
        "sslmode",
    )
    parameters: dict[str, Any] = {
        "host": host,
        "user": user,
        "password": password,
        "dbname": database,
        "port": port,
        "sslmode": sslmode,
        "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT_SECONDS", "10")),
        "application_name": "act-migrator",
    }
    root_certificate = secret.get("sslrootcert") or os.getenv("DB_SSLROOTCERT")
    if root_certificate:
        parameters["sslrootcert"] = root_certificate
    dsn = require_tls(make_conninfo(**parameters))
    return DatabaseSettings(
        dsn=dsn,
        host=host,
        port=port,
        dbname=database,
        sslmode=sslmode,
    )


def database_settings_from_environment(
    *,
    client: Any | None = None,
) -> DatabaseSettings:
    direct = os.getenv("DATABASE_URL")
    allow_insecure = os.getenv("ACT_ALLOW_INSECURE_TEST_DATABASE") == "1"
    if direct:
        dsn = require_tls(direct, allow_insecure_test_database=allow_insecure)
        parameters = conninfo_to_dict(dsn)
        raw_database = parameters.get("dbname") or os.getenv("DB_NAME")
        raw_host = parameters.get("host")
        if not raw_database:
            raise MigrationError("DATABASE_URL or DB_NAME must identify a database")
        if not raw_host:
            raise MigrationError("DATABASE_URL must identify a database host")
        database = _required_text(raw_database, "DATABASE_URL", "database name")
        host = _required_text(raw_host, "DATABASE_URL", "host")
        if "dbname" not in parameters:
            dsn = make_conninfo(dsn, dbname=database)
        port = _validated_port(parameters.get("port", 5432), "DATABASE_URL")
        sslmode = _required_text(
            parameters.get("sslmode", "disable"),
            "DATABASE_URL",
            "sslmode",
        )
        return DatabaseSettings(
            dsn=dsn,
            host=host,
            port=port,
            dbname=database,
            sslmode=sslmode,
        )

    secret_id = os.getenv("DB_SECRET_ID")
    if not secret_id:
        raise MigrationError("DB_SECRET_ID or DATABASE_URL is required")
    return database_settings_from_secret(
        secret_id,
        os.getenv("AWS_REGION"),
        client=client,
        database_name=os.getenv("DB_NAME"),
    )


def dsn_from_environment() -> str:
    return database_settings_from_environment().dsn
