#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
"""Build a container from an archive containing only files committed at HEAD."""

from __future__ import annotations

import argparse
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def repository_path(value: str) -> PurePosixPath:
    """Parse one normalized, repository-relative path."""

    path = PurePosixPath(value)
    if value == ".":
        return path
    if path.is_absolute() or value != path.as_posix() or value.startswith("../"):
        raise argparse.ArgumentTypeError("path must be normalized and repository-relative")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dockerfile", required=True, type=repository_path)
    parser.add_argument("--context", default=PurePosixPath("."), type=repository_path)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--no-pull",
        action="store_true",
        help="do not refresh the base image (intended only for disconnected local tests)",
    )
    return parser


def archive_head(git: str, context: PurePosixPath) -> bytes:
    """Archive the selected committed tree at HEAD."""

    treeish = "HEAD" if context == PurePosixPath(".") else f"HEAD:{context.as_posix()}"
    result = subprocess.run(  # noqa: S603 - git is an absolute executable path.
        (git, "-C", str(ROOT), "archive", "--format=tar", treeish),
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git archive failed: {detail}")
    return result.stdout


def dockerfile_in_context(
    dockerfile: PurePosixPath,
    context: PurePosixPath,
) -> PurePosixPath:
    """Return the Dockerfile path inside the archived context."""

    if context == PurePosixPath("."):
        return dockerfile
    try:
        return dockerfile.relative_to(context)
    except ValueError as exc:
        raise ValueError(f"{dockerfile} is outside build context {context}") from exc


def main() -> int:
    args = build_parser().parse_args()
    git = shutil.which("git")
    docker = shutil.which("docker")
    if git is None or docker is None:
        missing = "git" if git is None else "docker"
        sys.stderr.write(f"error: required executable not found: {missing}\n")
        return 2

    try:
        archive = archive_head(git, args.context)
        relative_dockerfile = dockerfile_in_context(args.dockerfile, args.context)
        with tempfile.TemporaryDirectory(prefix="portscanner-context-") as temporary_directory:
            context_directory = Path(temporary_directory)
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
                tar.extractall(context_directory, filter="data")
            dockerfile = context_directory / relative_dockerfile.as_posix()
            if not dockerfile.is_file():
                raise RuntimeError(f"Dockerfile is not committed at HEAD: {args.dockerfile}")

            command = [docker, "build"]
            if not args.no_pull:
                command.append("--pull")
            command.extend(
                (
                    "--file",
                    str(dockerfile),
                    "--tag",
                    args.tag,
                    str(context_directory),
                )
            )
            result = subprocess.run(command, check=False)  # noqa: S603
            return result.returncode
    except (OSError, RuntimeError, tarfile.TarError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
