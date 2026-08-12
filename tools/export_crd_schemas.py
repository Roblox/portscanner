#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
"""Export CRD OpenAPI schemas for fail-closed kubeconform validation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path

import yaml


def _strict_schema(value: object) -> object:
    if isinstance(value, list):
        return [_strict_schema(item) for item in value]
    if not isinstance(value, dict):
        return value

    strict = {key: _strict_schema(item) for key, item in value.items()}
    if (
        strict.get("type") == "object"
        and isinstance(strict.get("properties"), dict)
        and "additionalProperties" not in strict
        and strict.get("x-kubernetes-preserve-unknown-fields") is not True
    ):
        strict["additionalProperties"] = False
    return strict


def export_schemas(crd_paths: Iterable[Path], output_directory: Path) -> tuple[Path, ...]:
    """Export every versioned CRD schema using kubeconform's lookup convention."""

    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for crd_path in crd_paths:
        documents = yaml.safe_load_all(crd_path.read_text(encoding="utf-8"))
        for document in documents:
            if not isinstance(document, dict) or document.get("kind") != "CustomResourceDefinition":
                raise ValueError(f"{crd_path} does not contain only CustomResourceDefinitions")
            spec = document.get("spec")
            if not isinstance(spec, dict):
                raise ValueError(f"{crd_path} has no CRD spec")
            names = spec.get("names")
            versions = spec.get("versions")
            if not isinstance(names, dict) or not isinstance(names.get("kind"), str):
                raise ValueError(f"{crd_path} has no CRD kind")
            if not isinstance(versions, list) or not versions:
                raise ValueError(f"{crd_path} has no CRD versions")

            kind = names["kind"].lower()
            for version in versions:
                if not isinstance(version, dict) or not isinstance(version.get("name"), str):
                    raise ValueError(f"{crd_path} has an invalid CRD version")
                schema_container = version.get("schema")
                if not isinstance(schema_container, dict):
                    raise ValueError(f"{crd_path} version {version['name']} has no schema")
                schema = schema_container.get("openAPIV3Schema")
                if not isinstance(schema, dict):
                    raise ValueError(f"{crd_path} version {version['name']} has no OpenAPI schema")

                output = output_directory / f"{kind}_{version['name']}.json"
                output.write_text(
                    json.dumps(_strict_schema(schema), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                outputs.append(output)

    if not outputs:
        raise ValueError("no CRD schemas were exported")
    return tuple(outputs)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("crds", nargs="+", type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    export_schemas(args.crds, args.output_directory)


if __name__ == "__main__":
    main()
