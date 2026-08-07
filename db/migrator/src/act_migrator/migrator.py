"""Small, strict migration runner with checksum verification."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg.rows import tuple_row

_MIGRATION_FILE = re.compile(
    r"^(?P<version>[0-9]{6})_(?P<name>[a-z0-9][a-z0-9_]*)\.(?P<direction>up|down)\.sql$"
)
_LOCK_NAMESPACE = "act-data-plane-schema-migrations-v1"
_POSTGRESQL_15_SERVER_VERSION = 150000


class MigrationError(RuntimeError):
    """A migration invariant or execution failed."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: str
    name: str
    up_sql: str
    down_sql: str
    checksum: str


def _checksum(up_sql: bytes, down_sql: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(b"up\0")
    digest.update(up_sql)
    digest.update(b"\0down\0")
    digest.update(down_sql)
    return digest.hexdigest()


def discover_migrations(directory: str | Path) -> list[Migration]:
    """Load paired migrations and reject gaps, duplicates, or malformed SQL names."""
    root = Path(directory)
    if not root.is_dir():
        raise MigrationError(f"migration directory does not exist: {root}")

    pairs: dict[str, dict[str, tuple[str, bytes]]] = {}
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        match = _MIGRATION_FILE.fullmatch(path.name)
        if path.suffix == ".sql" and match is None:
            raise MigrationError(f"invalid migration filename: {path.name}")
        if match is None:
            continue
        version = match.group("version")
        name = match.group("name")
        direction = match.group("direction")
        slot = pairs.setdefault(version, {})
        if direction in slot:
            raise MigrationError(f"duplicate {direction} migration for {version}")
        slot[direction] = (name, path.read_bytes())

    migrations: list[Migration] = []
    for version in sorted(pairs):
        pair = pairs[version]
        if set(pair) != {"up", "down"}:
            missing = "down" if "up" in pair else "up"
            raise MigrationError(f"migration {version} is missing its {missing} file")
        up_name, up_bytes = pair["up"]
        down_name, down_bytes = pair["down"]
        if up_name != down_name:
            raise MigrationError(f"migration {version} up/down names do not match")
        migrations.append(
            Migration(
                version=version,
                name=up_name,
                up_sql=up_bytes.decode("utf-8"),
                down_sql=down_bytes.decode("utf-8"),
                checksum=_checksum(up_bytes, down_bytes),
            )
        )

    if not migrations:
        raise MigrationError(f"no migrations found in {root}")
    return migrations


def advisory_lock_key(database_name: str) -> int:
    value = hashlib.sha256(f"{_LOCK_NAMESPACE}:{database_name}".encode()).digest()[:8]
    return int.from_bytes(value, byteorder="big", signed=True)


class Migrator:
    """Apply a fully ordered migration set on one PostgreSQL connection."""

    def __init__(
        self,
        connection: psycopg.Connection,
        migrations: Sequence[Migration],
    ) -> None:
        if not migrations:
            raise MigrationError("at least one migration is required")
        self.connection = connection
        self.migrations = list(migrations)
        self.connection.autocommit = True
        if self.connection.info.server_version < _POSTGRESQL_15_SERVER_VERSION:
            raise MigrationError("PostgreSQL 15 or newer is required")

    @contextmanager
    def _advisory_lock(self) -> Iterator[None]:
        with self.connection.cursor(row_factory=tuple_row) as cursor:
            cursor.execute("SELECT current_database()")
            row = cursor.fetchone()
            if row is None or not row:
                raise MigrationError("database connection returned no current database name")
            database_name = row[0]
            if not isinstance(database_name, str) or not database_name:
                raise MigrationError("database connection returned no current database name")
        lock_key = advisory_lock_key(database_name)
        self.connection.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
        try:
            yield
        finally:
            self.connection.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))

    def _ensure_metadata(self) -> None:
        with self.connection.transaction():
            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS public.schema_migrations (
                    version TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum CHAR(64) NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    execution_ms BIGINT NOT NULL,
                    CONSTRAINT schema_migrations_version_valid
                        CHECK (version ~ '^[0-9]{6}$'),
                    CONSTRAINT schema_migrations_checksum_valid
                        CHECK (checksum ~ '^[0-9a-f]{64}$'),
                    CONSTRAINT schema_migrations_execution_nonnegative
                        CHECK (execution_ms >= 0)
                )
                """
            )
            self.connection.execute("REVOKE ALL ON TABLE public.schema_migrations FROM PUBLIC")

    def _applied(self) -> dict[str, tuple[str, str]]:
        with self.connection.cursor(row_factory=tuple_row) as cursor:
            cursor.execute(
                """
                SELECT version, name, checksum
                FROM public.schema_migrations
                ORDER BY version
                """
            )
            rows = cursor.fetchall()
        return {row[0]: (row[1], row[2].strip()) for row in rows}

    def _verify(self, applied: dict[str, tuple[str, str]]) -> None:
        available = {migration.version: migration for migration in self.migrations}
        for version, (name, checksum) in applied.items():
            migration = available.get(version)
            if migration is None:
                raise MigrationError(f"applied migration {version} is absent from this artifact")
            if name != migration.name or checksum != migration.checksum:
                raise MigrationError(f"checksum mismatch for migration {version}")

        applied_versions = sorted(applied)
        expected_prefix = [
            migration.version for migration in self.migrations[: len(applied_versions)]
        ]
        if applied_versions != expected_prefix:
            raise MigrationError("applied migrations are not a contiguous ordered prefix")

    def up(self, target: str | None = None) -> list[str]:
        known_versions = {migration.version for migration in self.migrations}
        if target is not None and target not in known_versions:
            raise MigrationError(f"unknown target migration: {target}")

        applied_now: list[str] = []
        with self._advisory_lock():
            self._ensure_metadata()
            applied = self._applied()
            self._verify(applied)
            for migration in self.migrations:
                if target is not None and migration.version > target:
                    break
                if migration.version in applied:
                    continue
                started = time.monotonic()
                try:
                    with self.connection.transaction():
                        self.connection.execute(migration.up_sql, prepare=False)
                        elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
                        self.connection.execute(
                            """
                            INSERT INTO public.schema_migrations (
                                version, name, checksum, execution_ms
                            )
                            VALUES (%s, %s, %s, %s)
                            """,
                            (
                                migration.version,
                                migration.name,
                                migration.checksum,
                                elapsed_ms,
                            ),
                        )
                except Exception as error:
                    raise MigrationError(f"migration {migration.version} up failed") from error
                applied_now.append(migration.version)
        return applied_now

    def down(
        self,
        *,
        steps: int | None = 1,
        target: str | None = None,
    ) -> list[str]:
        if target is not None and steps not in (None, 1):
            raise MigrationError("use either target or steps for down migration")
        if target is not None:
            versions = {migration.version for migration in self.migrations}
            if target != "000000" and target not in versions:
                raise MigrationError(f"unknown down target: {target}")
        elif steps is None or steps < 1:
            raise MigrationError("down steps must be at least one")

        reverted: list[str] = []
        by_version = {migration.version: migration for migration in self.migrations}
        with self._advisory_lock():
            self._ensure_metadata()
            applied = self._applied()
            self._verify(applied)
            selected = sorted(applied, reverse=True)
            if target is not None:
                selected = [version for version in selected if version > target]
            else:
                selected = selected[:steps]

            for version in selected:
                migration = by_version[version]
                try:
                    with self.connection.transaction():
                        self.connection.execute(migration.down_sql, prepare=False)
                        self.connection.execute(
                            "DELETE FROM public.schema_migrations WHERE version = %s",
                            (version,),
                        )
                except Exception as error:
                    raise MigrationError(f"migration {version} down failed") from error
                reverted.append(version)
        return reverted
