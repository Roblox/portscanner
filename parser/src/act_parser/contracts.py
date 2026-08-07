"""Adapter to the authoritative shared ScanResult contract package."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any


class ContractValidationError(ValueError):
    """The shared contract rejected an event envelope."""


def _mapping(value: Any, original: Mapping[str, Any]) -> Mapping[str, Any]:
    if value is None:
        return original
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        mapped = model_dump(mode="json")
        if isinstance(mapped, Mapping):
            return mapped
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        mapped = to_dict()
        if isinstance(mapped, Mapping):
            return mapped
    raise ContractValidationError("shared ScanResult validator returned an unsupported value")


def validate_scan_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate with the public ScanResultEnvelope validator."""

    try:
        contracts = importlib.import_module("portscanner_contracts")
        validator = getattr(contracts, "validate_scan_result", None)
        if not callable(validator):
            raise RuntimeError("shared package does not export validate_scan_result")
        return _mapping(validator(payload), payload)
    except ContractValidationError:
        raise
    except Exception as error:
        raise ContractValidationError("ScanResult contract validation failed") from error


def validate_finding(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate with the public Finding payload validator."""

    try:
        contracts = importlib.import_module("portscanner_contracts")
        validator = getattr(contracts, "validate_finding", None)
        if not callable(validator):
            raise RuntimeError("shared package does not export validate_finding")
        return _mapping(validator(payload), payload)
    except ContractValidationError:
        raise
    except Exception as error:
        raise ContractValidationError("Finding contract validation failed") from error


def parse_target_event(payload: Mapping[str, Any]) -> Any:
    """Parse a work event or removal through the authoritative shared parser."""
    try:
        contracts = importlib.import_module("portscanner_contracts")
        parser = getattr(contracts, "parse_target_event", None)
        if not callable(parser):
            raise RuntimeError("portscanner_contracts does not expose parse_target_event")
        return parser(payload)
    except ContractValidationError:
        raise
    except RuntimeError:
        raise
    except Exception as error:
        raise ContractValidationError("TargetEvent contract validation failed") from error
