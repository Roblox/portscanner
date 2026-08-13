from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from act_migrator.config import database_settings_from_secret, require_tls
from act_migrator.migrator import MigrationError, discover_migrations, migration_set_checksum


def _write_pair(root: Path, version: str, name: str, up: str, down: str) -> None:
    (root / f"{version}_{name}.up.sql").write_text(up, encoding="utf-8")
    (root / f"{version}_{name}.down.sql").write_text(down, encoding="utf-8")


def test_repository_migration_artifact_is_one_baseline_pair() -> None:
    migrations_path = Path(__file__).resolve().parents[2] / "migrations"

    migrations = discover_migrations(migrations_path)

    assert [(migration.version, migration.name) for migration in migrations] == [("000001", "core")]
    checksums = [migration.checksum for migration in migrations]
    checksums.append(migration_set_checksum(migrations_path))
    assert all(
        len(checksum) == 64 and set(checksum) <= set("0123456789abcdef") for checksum in checksums
    )
    assert sorted(path.name for path in migrations_path.iterdir()) == [
        "000001_core.down.sql",
        "000001_core.up.sql",
    ]


def test_discovers_ordered_pairs_and_hashes_both_directions(tmp_path: Path) -> None:
    _write_pair(tmp_path, "000002", "second", "SELECT 2;", "SELECT -2;")
    _write_pair(tmp_path, "000001", "first", "SELECT 1;", "SELECT -1;")

    migrations = discover_migrations(tmp_path)
    original_checksum = migrations[0].checksum
    assert [migration.version for migration in migrations] == ["000001", "000002"]

    (tmp_path / "000001_first.down.sql").write_text("SELECT 0;", encoding="utf-8")
    assert discover_migrations(tmp_path)[0].checksum != original_checksum


def test_migration_set_checksum_binds_names_order_and_contents(tmp_path: Path) -> None:
    _write_pair(tmp_path, "000001", "first", "SELECT 1;", "SELECT -1;")
    original = migration_set_checksum(tmp_path)

    (tmp_path / "000001_first.down.sql").write_text("SELECT 0;", encoding="utf-8")
    assert migration_set_checksum(tmp_path) != original


def test_rejects_symlinked_migration_files_from_checksum_and_discovery(tmp_path: Path) -> None:
    source = tmp_path / "source.sql"
    source.write_text("SELECT 1;", encoding="utf-8")
    (tmp_path / "000001_link.up.sql").symlink_to(source)
    (tmp_path / "000001_link.down.sql").symlink_to(source)

    with pytest.raises(MigrationError, match="contains a symlink"):
        migration_set_checksum(tmp_path)
    with pytest.raises(MigrationError, match="contains a symlink"):
        discover_migrations(tmp_path)


def test_rejects_unpaired_and_malformed_migrations(tmp_path: Path) -> None:
    (tmp_path / "000001_first.up.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(MigrationError, match="missing its down"):
        discover_migrations(tmp_path)
    with pytest.raises(MigrationError, match="missing its down"):
        migration_set_checksum(tmp_path)

    (tmp_path / "000001_first.down.sql").write_text("SELECT -1;", encoding="utf-8")
    (tmp_path / "bad.sql").write_text("SELECT 0;", encoding="utf-8")
    with pytest.raises(MigrationError, match="invalid migration filename"):
        discover_migrations(tmp_path)


def test_rejects_migration_version_gaps_from_checksum_and_discovery(tmp_path: Path) -> None:
    _write_pair(tmp_path, "000001", "first", "SELECT 1;", "SELECT -1;")
    _write_pair(tmp_path, "000003", "third", "SELECT 3;", "SELECT -3;")

    with pytest.raises(MigrationError, match="contiguous"):
        discover_migrations(tmp_path)
    with pytest.raises(MigrationError, match="contiguous"):
        migration_set_checksum(tmp_path)


def test_rejects_non_migration_artifacts_from_checksum_and_discovery(tmp_path: Path) -> None:
    _write_pair(tmp_path, "000001", "first", "SELECT 1;", "SELECT -1;")
    (tmp_path / "README.txt").write_text("not part of the release", encoding="utf-8")

    with pytest.raises(MigrationError, match="invalid migration"):
        migration_set_checksum(tmp_path)
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
