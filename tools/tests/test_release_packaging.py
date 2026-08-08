# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = {
    "inventory": "portscanner-inventory",
    "generator": "portscanner-generator",
    "parser": "portscanner-parser",
    "processor": "portscanner-processor",
    "db/migrator": "portscanner-migrator",
    "scanner/nmap": "portscanner-scanner",
}


def requirement_records(content: str) -> list[str]:
    records: list[str] = []
    current = ""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current += line.removesuffix("\\").strip() + " "
        if not line.endswith("\\"):
            records.append(current.strip())
            current = ""
    if current:
        records.append(current.strip())
    return records


class ReleasePackagingTests(unittest.TestCase):
    def test_component_metadata_packages_the_repository_license(self) -> None:
        repository_license = (ROOT / "LICENSE").read_bytes()
        for component in (*COMPONENTS, "contracts"):
            with self.subTest(component=component):
                component_root = ROOT / component
                metadata = tomllib.loads(
                    (component_root / "pyproject.toml").read_text(encoding="utf-8")
                )["project"]
                self.assertEqual(metadata["license"], "MIT")
                self.assertEqual(metadata["license-files"], ["LICENSE"])
                self.assertEqual((component_root / "LICENSE").read_bytes(), repository_license)

    def test_runtime_exports_are_exact_hash_pins(self) -> None:
        for component in COMPONENTS:
            with self.subTest(component=component):
                content = (ROOT / component / "requirements-runtime.txt").read_text(
                    encoding="utf-8"
                )
                records = requirement_records(content)
                self.assertTrue(records)
                if component != "scanner/nmap":
                    self.assertTrue(any(record.startswith("awslambdaric==") for record in records))
                self.assertTrue(any(record.startswith("boto3==") for record in records))
                self.assertTrue(any(record.startswith("botocore==") for record in records))
                for record in records:
                    self.assertRegex(record, r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?==[^ ]+")
                    self.assertIn("--hash=sha256:", record)
                    self.assertNotIn(" @ ", record)

    def test_build_backend_export_is_exact_and_hashed(self) -> None:
        records = requirement_records((ROOT / "requirements-build.txt").read_text(encoding="utf-8"))
        self.assertTrue(any(record.startswith("hatchling==1.27.0") for record in records))
        self.assertTrue(any(record.startswith("setuptools==80.9.0") for record in records))
        for record in records:
            self.assertIn("--hash=sha256:", record)

    def test_lambda_dockerfiles_enforce_lock_and_license_controls(self) -> None:
        for component in COMPONENTS:
            with self.subTest(component=component):
                dockerfile = (ROOT / component / "Dockerfile").read_text(encoding="utf-8")
                self.assertIn("requirements-build.txt", dockerfile)
                self.assertIn(f"{component}/requirements-runtime.txt", dockerfile)
                self.assertIn("python:3.12-slim-bookworm", dockerfile)
                self.assertIn("@sha256:", dockerfile)
                self.assertIn("--require-hashes", dockerfile)
                self.assertIn("--force-reinstall", dockerfile)
                self.assertIn("--no-build-isolation", dockerfile)
                self.assertIn("--no-deps", dockerfile)
                self.assertIn(
                    "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/",
                    dockerfile,
                )
                self.assertIn("USER 65532:65532", dockerfile)
                if component != "scanner/nmap":
                    self.assertIn(
                        'ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]',
                        dockerfile,
                    )

    def test_docker_context_defenses_exclude_local_secrets_and_ide_files(self) -> None:
        required_patterns = {
            "**/.aws",
            "**/.env",
            "**/.git-credentials",
            "**/.idea",
            "**/.kube",
            "**/.ssh",
            "**/.vscode",
            "**/override.tf",
            "**/credentials.json",
            "**/*.pem",
        }
        for relative_path in (".dockerignore", "operator/.dockerignore"):
            with self.subTest(path=relative_path):
                patterns = {
                    line.strip()
                    for line in (ROOT / relative_path).read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")
                }
                self.assertTrue(required_patterns <= patterns)

    def test_container_workflow_watches_shared_build_inputs(self) -> None:
        workflow = (ROOT / ".github/workflows/containers.yml").read_text(encoding="utf-8")
        for path in (
            '".dockerignore"',
            '"contracts/**"',
            '"db/migrations/**"',
            '"uv.lock"',
            '"tools/build_tracked_image.py"',
            '"tools/export_runtime_requirements.py"',
        ):
            with self.subTest(path=path):
                self.assertIn(path, workflow)


if __name__ == "__main__":
    unittest.main()
