"""Provision the least-privilege PostgreSQL runtime role and its AWS secret."""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import psycopg
from botocore.exceptions import ClientError
from psycopg import sql

from .config import DatabaseSettings
from .migrator import MigrationError, migration_advisory_lock

DEFAULT_APPLICATION_USERNAME = "portscanner_runtime"
_PASSWORD_BYTES = 48
_MINIMUM_PASSWORD_LENGTH = 32
_POSTGRESQL_IDENTIFIER_BYTES = 63


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    role_created: bool
    secret_updated: bool


def _validate_username(username: str) -> str:
    if (
        not username
        or username != username.strip()
        or "\x00" in username
        or len(username.encode("utf-8")) > _POSTGRESQL_IDENTIFIER_BYTES
    ):
        raise MigrationError("DB_APPLICATION_USERNAME is not a valid PostgreSQL role name")
    return username


def _secret_text(response: Mapping[str, Any]) -> str | None:
    if "SecretString" in response:
        value = response["SecretString"]
        if not isinstance(value, str):
            raise MigrationError("application secret string is malformed")
        return value or None
    if "SecretBinary" in response:
        raw = response["SecretBinary"]
        if isinstance(raw, str):
            try:
                raw = base64.b64decode(raw, validate=True)
            except ValueError as error:
                raise MigrationError("application secret binary is malformed") from error
        try:
            return bytes(raw).decode("utf-8") or None
        except (TypeError, UnicodeDecodeError) as error:
            raise MigrationError("application secret binary is malformed") from error
    return None


def _read_application_secret(client: Any, secret_id: str) -> Mapping[str, Any] | None:
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code", ""))
        if code == "ResourceNotFoundException":
            return None
        raise
    encoded = _secret_text(response)
    if encoded is None:
        return None
    try:
        value = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise MigrationError("application secret is not valid JSON") from error
    if not isinstance(value, dict):
        raise MigrationError("application secret must contain a JSON object")
    return value


def _stored_password(
    secret: Mapping[str, Any] | None,
    username: str,
    password_factory: Callable[[], str],
) -> str:
    if secret is None:
        password = password_factory()
        if not isinstance(password, str) or len(password) < _MINIMUM_PASSWORD_LENGTH:
            raise MigrationError("generated application password is not sufficiently strong")
        return password

    stored_username = secret.get("username")
    if stored_username not in (None, username):
        raise MigrationError("application secret username does not match configuration")
    stored_password = secret.get("password")
    if not isinstance(stored_password, str) or not stored_password:
        raise MigrationError("application secret value has no password")
    return stored_password


def _repair_role(
    connection: psycopg.Connection[Any],
    username: str,
    password: str,
) -> bool:
    identifier = sql.Identifier(username)
    try:
        with connection.transaction():
            exists = connection.execute(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s",
                (username,),
            ).fetchone()
            if exists is None:
                connection.execute(sql.SQL("CREATE ROLE {}").format(identifier))
            connection.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(identifier, sql.Literal(password)),
            )
            connection.execute("SELECT act.grant_application_role(%s::NAME)", (username,))
    except psycopg.Error:
        raise MigrationError("application database role provisioning failed") from None
    return exists is None


def _secret_payload(
    database: DatabaseSettings,
    username: str,
    password: str,
) -> dict[str, Any]:
    return {
        "host": database.host,
        "port": database.port,
        "dbname": database.dbname,
        "username": username,
        "password": password,
        "sslmode": database.sslmode,
    }


def provision_application_credentials(
    connection: psycopg.Connection[Any],
    secrets_client: Any,
    *,
    database: DatabaseSettings,
    application_secret_id: str,
    application_username: str = DEFAULT_APPLICATION_USERNAME,
    password_factory: Callable[[], str] | None = None,
) -> ProvisioningResult:
    """Repair one LOGIN role and synchronize its normalized secret without logging values."""
    if not application_secret_id:
        raise MigrationError("DB_APPLICATION_SECRET_ID is required")
    username = _validate_username(application_username)
    with migration_advisory_lock(connection):
        current_secret = _read_application_secret(secrets_client, application_secret_id)
        factory = password_factory or (lambda: secrets.token_urlsafe(_PASSWORD_BYTES))
        password = _stored_password(current_secret, username, factory)
        role_created = _repair_role(connection, username, password)

        payload = _secret_payload(database, username, password)
        secret_updated = current_secret != payload
        if secret_updated:
            secrets_client.put_secret_value(
                SecretId=application_secret_id,
                SecretString=json.dumps(
                    payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            )
        return ProvisioningResult(role_created=role_created, secret_updated=secret_updated)
