from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from act_migrator.config import database_settings_from_secret, require_tls
from act_migrator.migrator import MigrationError, discover_migrations


def _write_pair(root: Path, version: str, name: str, up: str, down: str) -> None:
    (root / f"{version}_{name}.up.sql").write_text(up, encoding="utf-8")
    (root / f"{version}_{name}.down.sql").write_text(down, encoding="utf-8")


def test_discovers_ordered_pairs_and_hashes_both_directions(tmp_path: Path) -> None:
    _write_pair(tmp_path, "000002", "second", "SELECT 2;", "SELECT -2;")
    _write_pair(tmp_path, "000001", "first", "SELECT 1;", "SELECT -1;")

    migrations = discover_migrations(tmp_path)
    original_checksum = migrations[0].checksum
    assert [migration.version for migration in migrations] == ["000001", "000002"]

    (tmp_path / "000001_first.down.sql").write_text("SELECT 0;", encoding="utf-8")
    assert discover_migrations(tmp_path)[0].checksum != original_checksum


def test_rejects_unpaired_and_malformed_migrations(tmp_path: Path) -> None:
    (tmp_path / "000001_first.up.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(MigrationError, match="missing its down"):
        discover_migrations(tmp_path)

    (tmp_path / "000001_first.down.sql").write_text("SELECT -1;", encoding="utf-8")
    (tmp_path / "bad.sql").write_text("SELECT 0;", encoding="utf-8")
    with pytest.raises(MigrationError, match="invalid migration filename"):
        discover_migrations(tmp_path)


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_tls_modes_are_accepted(mode: str) -> None:
    dsn = f"postgresql://user:password@db.example/test?sslmode={mode}"
    assert require_tls(dsn) == dsn


def test_non_tls_dsn_is_rejected() -> None:
    with pytest.raises(MigrationError, match="sslmode"):
        require_tls("postgresql://user:password@db.example/test?sslmode=disable")


def test_master_secret_uses_database_name_fallback() -> None:
    class Secrets:
        def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["SecretId"] == "master-secret"
            return {
                "SecretString": (
                    '{"host":"db.example","port":5432,"username":"master","password":"not-logged"}'
                )
            }

    settings = database_settings_from_secret(
        "master-secret",
        client=Secrets(),
        database_name="portscanner",
    )

    assert settings.host == "db.example"
    assert settings.port == 5432
    assert settings.dbname == "portscanner"
    assert settings.sslmode == "require"


def test_master_secret_rejects_non_text_connection_fields() -> None:
    class Secrets:
        def get_secret_value(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "SecretString": (
                    '{"host":123,"port":5432,"username":"master",'
                    '"password":"not-logged","dbname":"portscanner"}'
                )
            }

    with pytest.raises(MigrationError, match="host must be a non-empty string"):
        database_settings_from_secret("master-secret", client=Secrets())
