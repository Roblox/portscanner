"""Small Kubernetes custom-object boundary used by the dispatcher."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any, Protocol

from .config import GeneratorConfig
from .scanner_resource import TARGET_HASH_LABEL

_HASH_RE = re.compile(r"^[0-9a-f]{52}$")


class CreateResult(StrEnum):
    CREATED = "created"
    ALREADY_EXISTS = "already_exists"


class ScannerClient(Protocol):
    def create(self, body: Mapping[str, Any]) -> CreateResult:
        """Create a Scanner or report its deterministic-name duplicate."""

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
            if _http_status(error) == 409:
                return CreateResult.ALREADY_EXISTS
            raise
        return CreateResult.CREATED

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
