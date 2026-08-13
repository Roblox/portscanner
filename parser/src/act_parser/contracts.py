"""Error translation around the required Portscanner contract package."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import portscanner_contracts


class ContractValidationError(ValueError):
    """The shared contract rejected an event envelope."""


def validate_scan_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        return portscanner_contracts.validate_scan_result(payload)
    except Exception as error:
        raise ContractValidationError("ScanResult contract validation failed") from error


def validate_finding(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        return portscanner_contracts.validate_finding(payload)
    except Exception as error:
        raise ContractValidationError("Finding contract validation failed") from error


def parse_target_event(payload: Mapping[str, Any]) -> Any:
    try:
        return portscanner_contracts.parse_target_event(payload)
    except Exception as error:
        raise ContractValidationError("TargetEvent contract validation failed") from error
