#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
"""Verify locked dependencies and licensing in a built Python Lambda image."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
LEGAL_FILES: Final = ("LICENSE", "THIRD_PARTY_NOTICES.md")
IMAGE_CHECK: Final = r"""
import hashlib
import importlib
import importlib.metadata
import json
import pathlib
import subprocess
import sys

expected_legal = json.loads(sys.argv[1])
distributions = json.loads(sys.argv[2])
handlers = json.loads(sys.argv[3])
for filename, expected_digest in expected_legal.items():
    path = pathlib.Path("/licenses") / filename
    if not path.is_file():
        raise SystemExit(f"missing image legal file: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_digest:
        raise SystemExit(f"image legal file differs from repository: {path}")

build_requirements = pathlib.Path("/opt/portscanner/requirements-build.txt")
if not build_requirements.is_file():
    raise SystemExit(f"missing frozen build requirements: {build_requirements}")

runtime_requirements = pathlib.Path("/opt/portscanner/requirements-runtime.txt")
if not runtime_requirements.is_file():
    raise SystemExit(f"missing frozen runtime requirements: {runtime_requirements}")
subprocess.run(
    [
        sys.executable,
        "-m",
        "pip",
        "--quiet",
        "install",
        "--dry-run",
        "--no-index",
        "--require-hashes",
        "--requirement",
        str(runtime_requirements),
    ],
    check=True,
)

for build_only_name in (
    "hatchling",
    "setuptools",
    "trove-classifiers",
    "pathspec",
    "packaging",
    "pluggy",
):
    try:
        importlib.metadata.distribution(build_only_name)
    except importlib.metadata.PackageNotFoundError:
        continue
    raise SystemExit(f"build-only distribution remains in runtime image: {build_only_name}")

for name in distributions:
    distribution = importlib.metadata.distribution(name)
    expression = distribution.metadata.get("License-Expression")
    if expression != "MIT":
        raise SystemExit(f"{name} has unexpected License-Expression: {expression!r}")
    files = [str(path) for path in distribution.files or ()]
    if not any(path.endswith(".dist-info/licenses/LICENSE") for path in files):
        raise SystemExit(f"{name} wheel metadata does not contain licenses/LICENSE")

for handler in handlers:
    module_name, separator, attribute_name = handler.rpartition(".")
    if not separator:
        raise SystemExit(f"invalid Lambda handler command: {handler}")
    module = importlib.import_module(module_name)
    resolved = getattr(module, attribute_name, None)
    if not callable(resolved):
        raise SystemExit(f"Lambda handler command does not resolve to a callable: {handler}")
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument(
        "--distribution",
        action="append",
        required=True,
        help="installed first-party distribution to inspect; may be repeated",
    )
    parser.add_argument(
        "--handler",
        action="append",
        default=[],
        help="Lambda handler command to import and resolve; may be repeated",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    docker = shutil.which("docker")
    if docker is None:
        sys.stderr.write("error: required executable not found: docker\n")
        return 2

    try:
        expected_legal = {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in LEGAL_FILES
        }
    except OSError as exc:
        sys.stderr.write(f"error: cannot read repository legal files: {exc}\n")
        return 2

    command = (
        docker,
        "run",
        "--rm",
        "--env",
        "AWS_EC2_METADATA_DISABLED=true",
        "--env",
        "AWS_REGION=us-east-1",
        "--entrypoint",
        "python",
        args.image,
        "-c",
        IMAGE_CHECK,
        json.dumps(expected_legal, sort_keys=True),
        json.dumps(args.distribution),
        json.dumps(args.handler),
    )
    result = subprocess.run(command, check=False)  # noqa: S603
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
