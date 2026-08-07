"""Small Kubernetes custom-object boundary used by the dispatcher."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any, Protocol

from .config import GeneratorConfig
from .scanner_resource import TARGET_HASH_LABEL

_HASH_RE = re.compile(r"^[0-9a-f]{52}$")
_SCANNER_SPEC_DEFAULTS = {
    "retryLimit": 0,
    "ttlSecondsAfterFinished": 3600,
}


class CreateResult(StrEnum):
    CREATED = "created"
    ALREADY_EXISTS = "already_exists"


class ScannerConflictError(RuntimeError):
    """A deterministic Scanner name is occupied by incompatible state."""


class ScannerClient(Protocol):
    def create(self, body: Mapping[str, Any]) -> CreateResult:
        """Create a Scanner or report its deterministic-name duplicate."""

    def get(self, name: str) -> Mapping[str, Any] | None:
        """Read one Scanner, returning none only when it is absent."""

    def list_for_target_hash(self, opaque_target_hash: str) -> Sequence[Mapping[str, Any]]:
        """List Scanner resources for one opaque target identity."""

    def delete(self, name: str) -> bool:
        """Delete a Scanner, returning false when it was already absent."""


def _http_status(error: Exception) -> int | None:
    status = getattr(error, "status", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _scanner_name(body: Mapping[str, Any]) -> str:
    metadata = body.get("metadata")
    name = metadata.get("name") if isinstance(metadata, Mapping) else None
    if not isinstance(name, str) or not name:
        raise ValueError("Scanner body has no metadata.name")
    return name


def _existing_matches(
    expected: Mapping[str, Any],
    existing: Mapping[str, Any],
) -> bool:
    expected_metadata = expected.get("metadata")
    existing_metadata = existing.get("metadata")
    if not isinstance(expected_metadata, Mapping) or not isinstance(
        existing_metadata,
        Mapping,
    ):
        return False
    if existing_metadata.get("name") != expected_metadata.get("name"):
        return False
    if existing_metadata.get("deletionTimestamp") is not None:
        return False

    expected_labels = expected_metadata.get("labels")
    existing_labels = existing_metadata.get("labels")
    if not isinstance(expected_labels, Mapping) or not isinstance(existing_labels, Mapping):
        return False
    if any(existing_labels.get(key) != value for key, value in expected_labels.items()):
        return False

    expected_spec = expected.get("spec")
    existing_spec = existing.get("spec")
    if not isinstance(expected_spec, Mapping) or not isinstance(existing_spec, Mapping):
        return False
    normalized_expected_spec = dict(expected_spec)
    normalized_existing_spec = dict(existing_spec)
    for key, value in _SCANNER_SPEC_DEFAULTS.items():
        normalized_expected_spec.setdefault(key, value)
        normalized_existing_spec.setdefault(key, value)
    if normalized_existing_spec != normalized_expected_spec:
        return False

    status = existing.get("status")
    outcome = status.get("outcome") if isinstance(status, Mapping) else None
    return not (isinstance(outcome, str) and outcome.lower() == "cancelled")


class KubernetesScannerClient:
    """Typed operations over ``CustomObjectsApi``."""

    def __init__(self, custom_objects_api: Any, config: GeneratorConfig) -> None:
        self._api = custom_objects_api
        self._config = config

    def create(self, body: Mapping[str, Any]) -> CreateResult:
        try:
            self._api.create_namespaced_custom_object(
                group=self._config.api_group,
                version=self._config.api_version,
                namespace=self._config.namespace,
                plural=self._config.plural,
                body=dict(body),
            )
        except Exception as error:
            if _http_status(error) != 409:
                raise
            name = _scanner_name(body)
            existing = self.get(name)
            if existing is None or not _existing_matches(body, existing):
                raise ScannerConflictError(
                    "existing Scanner does not match the deterministic request"
                ) from error
            return CreateResult.ALREADY_EXISTS
        return CreateResult.CREATED

    def get(self, name: str) -> Mapping[str, Any] | None:
        if not isinstance(name, str) or not name:
            raise ValueError("Scanner name must be a non-empty string")
        try:
            response = self._api.get_namespaced_custom_object(
                group=self._config.api_group,
                version=self._config.api_version,
                namespace=self._config.namespace,
                plural=self._config.plural,
                name=name,
            )
        except Exception as error:
            if _http_status(error) == 404:
                return None
            raise
        if not isinstance(response, Mapping):
            raise RuntimeError("Kubernetes get response is not an object")
        return response

    def list_for_target_hash(
        self,
        opaque_target_hash: str,
    ) -> Sequence[Mapping[str, Any]]:
        if not _HASH_RE.fullmatch(opaque_target_hash):
            raise ValueError("target hash is not a valid label value")
        results: list[Mapping[str, Any]] = []
        continuation: str | None = None
        seen_tokens: set[str] = set()
        while True:
            request: dict[str, Any] = {
                "group": self._config.api_group,
                "version": self._config.api_version,
                "namespace": self._config.namespace,
                "plural": self._config.plural,
                "label_selector": (f"{TARGET_HASH_LABEL}={opaque_target_hash}"),
            }
            if continuation is not None:
                request["_continue"] = continuation
            response = self._api.list_namespaced_custom_object(**request)
            if not isinstance(response, Mapping):
                raise RuntimeError("Kubernetes list response is not an object")
            items = response.get("items", [])
            if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
                raise RuntimeError("Kubernetes list response has invalid items")
            results.extend(items)

            metadata = response.get("metadata", {})
            if not isinstance(metadata, Mapping):
                raise RuntimeError("Kubernetes list response has invalid metadata")
            next_token = metadata.get("continue")
            if not next_token:
                return results
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise RuntimeError("Kubernetes list continuation is invalid")
            seen_tokens.add(next_token)
            continuation = next_token

    def delete(self, name: str) -> bool:
        if not isinstance(name, str) or not name:
            raise ValueError("Scanner name must be a non-empty string")
        try:
            self._api.delete_namespaced_custom_object(
                group=self._config.api_group,
                version=self._config.api_version,
                namespace=self._config.namespace,
                plural=self._config.plural,
                name=name,
                body={
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "propagationPolicy": "Foreground",
                },
            )
        except Exception as error:
            if _http_status(error) == 404:
                return False
            raise
        return True
