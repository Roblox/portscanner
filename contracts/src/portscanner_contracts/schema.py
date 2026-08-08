# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

"""JSON Schema helpers for checked-in public contract documents."""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter

from portscanner_contracts.models import ContractModel, TargetEventPayload

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_BASE_URI = "https://raw.githubusercontent.com/Roblox/portscanner/main/schemas"


def schema_document(
    model: type[ContractModel],
    filename: str,
) -> dict[str, Any]:
    """Build a draft 2020-12 schema with a stable public identifier."""

    if "/" in filename or not filename.endswith(".schema.json"):
        raise ValueError("filename must be a schema basename ending in .schema.json")
    generated = model.model_json_schema(mode="validation")
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_BASE_URI}/{filename}",
        **generated,
    }


def target_event_schema_document(filename: str) -> dict[str, Any]:
    """Build the public work/removal target-event union schema."""

    if "/" in filename or not filename.endswith(".schema.json"):
        raise ValueError("filename must be a schema basename ending in .schema.json")
    generated = TypeAdapter(TargetEventPayload).json_schema(mode="validation")
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_BASE_URI}/{filename}",
        **generated,
    }
