from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from act_migrator import handler
from act_migrator.config import DatabaseSettings


class _ConnectionContext:
    def __enter__(self) -> object:
        return object()

    def __exit__(self, *_args: object) -> None:
        return None


def _configure(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    provisions: list[dict[str, Any]] = []
    database = DatabaseSettings(
        dsn="postgresql://unused",
        host="database.example",
        port=5432,
        dbname="portscanner",
        sslmode="require",
    )

    class FakeMigrator:
        def __init__(self, _connection: object, _migrations: object) -> None:
            pass

        def up(self, *, target: str | None) -> list[str]:
            return [] if target is None else [target]

        def down(self, *, target: str | None, steps: int | None) -> list[str]:
            assert target is None
            assert steps == 1
            return ["000004"]

    monkeypatch.setenv("DB_APPLICATION_SECRET_ID", "application-secret")
    monkeypatch.setattr(
        handler,
        "discover_migrations",
        lambda _path: [SimpleNamespace(version="000004")],
    )
    monkeypatch.setattr(handler.boto3, "client", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        handler,
        "database_settings_from_environment",
        lambda **_kwargs: database,
    )
    monkeypatch.setattr(handler.psycopg, "connect", lambda _dsn: _ConnectionContext())
    monkeypatch.setattr(handler, "Migrator", FakeMigrator)
    monkeypatch.setattr(
        handler,
        "provision_application_credentials",
        lambda *_args, **kwargs: provisions.append(kwargs),
    )
    return provisions


def test_up_repairs_application_credentials_even_when_schema_is_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisions = _configure(monkeypatch)

    result = handler.lambda_handler({"direction": "up"}, None)

    assert result == {
        "direction": "up",
        "changed_versions": [],
        "latest_version": "000004",
        "credentials_repaired": True,
    }
    assert provisions[0]["application_secret_id"] == "application-secret"
    assert provisions[0]["application_username"] == "portscanner_runtime"


def test_down_never_alters_application_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provisions = _configure(monkeypatch)

    result = handler.lambda_handler({"direction": "down", "steps": 1}, None)

    assert result["changed_versions"] == ["000004"]
    assert not result["credentials_repaired"]
    assert provisions == []
