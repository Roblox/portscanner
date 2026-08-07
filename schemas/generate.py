# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

"""Regenerate checked-in JSON Schemas from the Python contract models."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from portscanner_contracts import (
    Finding,
    ScanResultEnvelope,
    schema_document,
    target_event_schema_document,
)

SchemaBuilder = Callable[[str], dict[str, Any]]

SCHEMAS: dict[str, SchemaBuilder] = {
    "finding.schema.json": lambda filename: schema_document(Finding, filename),
    "scan-result.schema.json": lambda filename: schema_document(ScanResultEnvelope, filename),
    "target-event.schema.json": target_event_schema_document,
}


def main() -> None:
    """Write deterministic draft 2020-12 schema documents."""

    output_directory = Path(__file__).resolve().parent
    for filename, builder in SCHEMAS.items():
        output = json.dumps(
            builder(filename),
            indent=2,
            sort_keys=True,
        )
        (output_directory / filename).write_text(f"{output}\n", encoding="utf-8")
        print(filename)


if __name__ == "__main__":
    main()
