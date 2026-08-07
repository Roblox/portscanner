"""Strict parser runtime configuration."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import boto3
from psycopg.conninfo import conninfo_to_dict, make_conninfo

_TLS_MODES = {"require", "verify-ca", "verify-full"}


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Settings:
    scan_result_bucket: str
    raw_result_bucket: str
    finding_bucket: str
    database_dsn: str
    max_envelope_bytes: int = 1_048_576
    max_xml_bytes: int = 67_108_864


@dataclass(frozen=True, slots=True)
class TargetEventSettings:
    target_event_bucket: str
    target_event_prefix: str
    finding_bucket: str
    database_dsn: str
    max_event_bytes: int = 65_536


def _secret_mapping(response: Mapping[str, Any]) -> Mapping[str, Any]:
    if "SecretString" in response:
        encoded = response["SecretString"]
    elif "SecretBinary" in response:
        raw = response["SecretBinary"]
        if isinstance(raw, str):
            raw = base64.b64decode(raw)
        encoded = bytes(raw).decode("utf-8")
    else:
        raise ConfigurationError("database secret has no value")
    try:
        secret = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("database secret is not valid JSON") from error
    if not isinstance(secret, dict):
        raise ConfigurationError("database secret must contain a JSON object")
    return secret


def _require_tls(dsn: str) -> str:
    parameters = conninfo_to_dict(dsn)
    if (
        parameters.get("sslmode") not in _TLS_MODES
        and os.getenv("ACT_ALLOW_INSECURE_TEST_DATABASE") != "1"
    ):
        raise ConfigurationError("database TLS is required")
    return dsn


def _database_dsn() -> str:
    direct = os.getenv("DATABASE_URL")
    if direct:
        return _require_tls(direct)
    secret_id = os.getenv("DB_SECRET_ID")
    if not secret_id:
        raise ConfigurationError("DB_SECRET_ID or DATABASE_URL is required")
    response = boto3.client("secretsmanager", region_name=os.getenv("AWS_REGION")).get_secret_value(
        SecretId=secret_id
    )
    secret = _secret_mapping(response)
    values = {
        "host": secret.get("host"),
        "user": secret.get("username") or secret.get("user"),
        "password": secret.get("password"),
        "dbname": secret.get("dbname") or secret.get("database"),
    }
    missing = [key for key, value in values.items() if value in (None, "")]
    if missing:
        raise ConfigurationError(f"database secret is missing fields: {', '.join(sorted(missing))}")
    parameters: dict[str, Any] = {
        **values,
        "port": secret.get("port", 5432),
        "sslmode": secret.get("sslmode") or os.getenv("DB_SSLMODE", "require"),
        "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT_SECONDS", "10")),
        "application_name": "act-parser",
    }
    root_certificate = secret.get("sslrootcert") or os.getenv("DB_SSLROOTCERT")
    if root_certificate:
        parameters["sslrootcert"] = root_certificate
    return _require_tls(make_conninfo(**parameters))


def database_dsn() -> str:
    """Return a secret-backed, TLS-required DSN for another ACT runtime."""
    return _database_dsn()


def load_settings() -> Settings:
    buckets = {
        "scan_result_bucket": os.getenv("SCAN_RESULT_BUCKET"),
        "raw_result_bucket": os.getenv("RAW_RESULT_BUCKET"),
        "finding_bucket": os.getenv("FINDING_BUCKET"),
    }
    missing = [key for key, value in buckets.items() if not value]
    if missing:
        raise ConfigurationError(f"missing bucket settings: {', '.join(sorted(missing))}")
    return Settings(
        scan_result_bucket=buckets["scan_result_bucket"] or "",
        raw_result_bucket=buckets["raw_result_bucket"] or "",
        finding_bucket=buckets["finding_bucket"] or "",
        database_dsn=database_dsn(),
        max_envelope_bytes=int(os.getenv("MAX_SCAN_RESULT_ENVELOPE_BYTES", "1048576")),
        max_xml_bytes=int(os.getenv("MAX_RAW_XML_BYTES", "67108864")),
    )


def load_target_event_settings() -> TargetEventSettings:
    values = {
        "target_event_bucket": os.getenv("TARGET_EVENT_BUCKET"),
        "target_event_prefix": os.getenv("TARGET_EVENT_PREFIX"),
        "finding_bucket": os.getenv("FINDING_BUCKET"),
    }
    missing = [key for key, value in values.items() if not value]
    if missing:
        raise ConfigurationError(f"missing target event settings: {', '.join(sorted(missing))}")
    return TargetEventSettings(
        target_event_bucket=values["target_event_bucket"] or "",
        target_event_prefix=values["target_event_prefix"] or "",
        finding_bucket=values["finding_bucket"] or "",
        database_dsn=database_dsn(),
        max_event_bytes=int(os.getenv("MAX_TARGET_EVENT_BYTES", "65536")),
    )
