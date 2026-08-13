#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
command -v uv >/dev/null 2>&1 || {
  echo "uv is required" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-migrator-package.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

uv build \
  --package portscanner-migrator \
  --sdist \
  --out-dir "${WORK_DIR}/dist"

sdists=("${WORK_DIR}"/dist/*.tar.gz)
[[ "${#sdists[@]}" -eq 1 && -f "${sdists[0]}" ]] || {
  echo "expected exactly one migrator source distribution" >&2
  exit 1
}

mkdir -p "${WORK_DIR}/sdist-source/migrations"
printf '%s\n' 'SELECT 999;' >"${WORK_DIR}/sdist-source/migrations/999999_untrusted.up.sql"
printf '%s\n' 'SELECT -999;' >"${WORK_DIR}/sdist-source/migrations/999999_untrusted.down.sql"
tar -xzf "${sdists[0]}" -C "${WORK_DIR}/sdist-source"
source_directories=("${WORK_DIR}"/sdist-source/portscanner_migrator-*/)
[[ "${#source_directories[@]}" -eq 1 && -d "${source_directories[0]}" ]] || {
  echo "expected exactly one extracted migrator source directory" >&2
  exit 1
}
uv build \
  --wheel \
  --out-dir "${WORK_DIR}/dist" \
  "${source_directories[0]}"

wheels=("${WORK_DIR}"/dist/*.whl)
[[ "${#wheels[@]}" -eq 1 && -f "${wheels[0]}" ]] || {
  echo "expected exactly one migrator wheel" >&2
  exit 1
}

uv venv --python 3.12 "${WORK_DIR}/venv"
VENV_PYTHON="${WORK_DIR}/venv/bin/python"
uv pip install \
  --python "${VENV_PYTHON}" \
  --require-hashes \
  --requirement "${ROOT}/db/migrator/requirements-runtime.txt"
uv pip install --python "${VENV_PYTHON}" --no-deps "${wheels[0]}"

(
  cd "${WORK_DIR}"
  unset MIGRATIONS_PATH
  REPOSITORY_MIGRATIONS="${ROOT}/db/migrations" "${VENV_PYTHON}" - <<'PY'
import os
from pathlib import Path

from act_migrator.handler import default_migrations_path
from act_migrator.migrator import discover_migrations, migration_set_checksum

repository = Path(os.environ["REPOSITORY_MIGRATIONS"])
packaged = default_migrations_path()
assert packaged.is_dir()
assert "site-packages/act_migrator/migrations" in packaged.as_posix()

source_entries = tuple(repository.iterdir())
packaged_entries = tuple(packaged.iterdir())
assert all(path.is_file() and not path.is_symlink() for path in source_entries)
assert all(path.is_file() and not path.is_symlink() for path in packaged_entries)
source_files = {path.name: path.read_bytes() for path in source_entries}
packaged_files = {path.name: path.read_bytes() for path in packaged_entries}
assert packaged_files == source_files
assert migration_set_checksum(packaged) == migration_set_checksum(repository)
assert len(discover_migrations(packaged)) == 1
PY
  "${WORK_DIR}/venv/bin/act-migrate" --help >/dev/null
)

echo "migrator package tests passed"
