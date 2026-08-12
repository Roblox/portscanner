# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    sys.modules["yaml"] = mock.Mock()

from tools import export_crd_schemas


class ExportCrdSchemasTests(unittest.TestCase):
    def test_exports_versioned_openapi_schema_for_kubeconform(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            tmp_path = Path(temporary_directory)
            crd = tmp_path / "widgets.yaml"
            crd.write_text("test fixture", encoding="utf-8")
            document = {
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "spec": {
                    "group": "example.test",
                    "names": {"kind": "Widget", "plural": "widgets"},
                    "scope": "Namespaced",
                    "versions": [
                        {
                            "name": "v1alpha1",
                            "served": True,
                            "storage": True,
                            "schema": {
                                "openAPIV3Schema": {
                                    "type": "object",
                                    "required": ["spec"],
                                    "properties": {
                                        "spec": {
                                            "type": "object",
                                            "properties": {"name": {"type": "string"}},
                                        }
                                    },
                                }
                            },
                        }
                    ],
                },
            }

            with mock.patch.object(
                export_crd_schemas.yaml,
                "safe_load_all",
                return_value=iter((document,)),
            ):
                outputs = export_crd_schemas.export_schemas((crd,), tmp_path / "schemas")

            self.assertEqual(outputs, (tmp_path / "schemas/widget_v1alpha1.json",))
            schema = json.loads(outputs[0].read_text(encoding="utf-8"))
            self.assertEqual(schema["required"], ["spec"])
            self.assertFalse(schema["additionalProperties"])
            self.assertFalse(schema["properties"]["spec"]["additionalProperties"])

    def test_rejects_crd_without_version_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            tmp_path = Path(temporary_directory)
            crd = tmp_path / "widgets.yaml"
            crd.write_text("test fixture", encoding="utf-8")
            document = {
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "spec": {
                    "names": {"kind": "Widget"},
                    "versions": [{"name": "v1"}],
                },
            }

            with (
                mock.patch.object(
                    export_crd_schemas.yaml,
                    "safe_load_all",
                    return_value=iter((document,)),
                ),
                self.assertRaisesRegex(ValueError, "has no schema"),
            ):
                export_crd_schemas.export_schemas((crd,), tmp_path / "schemas")
