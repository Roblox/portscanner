# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
"""Embed the repository migration set in migrator distributions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_MIGRATION_FILE = re.compile(r"^([0-9]{6})_([a-z0-9][a-z0-9_]*)\.(up|down)\.sql$")


class CustomBuildHook(BuildHookInterface):
    """Include one canonical SQL source in both sdists and wheels."""

    def initialize(self, _version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        repository_migrations = root.parent / "migrations"
        packaged_migrations = root / "migrations"
        source = packaged_migrations if packaged_migrations.is_dir() else repository_migrations
        if not source.is_dir():
            raise RuntimeError("canonical db/migrations directory was not found")

        destination = "migrations" if self.target_name == "sdist" else "act_migrator/migrations"
        force_include = build_data.setdefault("force_include", {})
        entries = sorted(source.iterdir())
        matches = [_MIGRATION_FILE.fullmatch(path.name) for path in entries]
        invalid = [
            path.name
            for path, match in zip(entries, matches, strict=True)
            if path.is_symlink() or not path.is_file() or match is None
        ]
        if invalid:
            raise RuntimeError(f"invalid canonical migration artifact: {invalid[0]}")
        migrations = entries
        if not migrations:
            raise RuntimeError("canonical db/migrations directory contains no SQL files")

        pairs: dict[str, tuple[str, set[str]]] = {}
        for match in matches:
            if match is None:
                raise RuntimeError("invalid canonical migration match")
            version, name, direction = match.groups()
            previous_name, directions = pairs.setdefault(version, (name, set()))
            if previous_name != name or direction in directions:
                raise RuntimeError(f"invalid canonical migration pair: {version}")
            directions.add(direction)
        versions = sorted(pairs)
        if versions != [f"{index:06d}" for index in range(1, len(versions) + 1)]:
            raise RuntimeError("canonical migration versions must be contiguous")
        incomplete = [
            version for version, (_, directions) in pairs.items() if directions != {"up", "down"}
        ]
        if incomplete:
            raise RuntimeError(f"incomplete canonical migration pair: {incomplete[0]}")

        for migration in migrations:
            force_include[str(migration)] = f"{destination}/{migration.name}"
