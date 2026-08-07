"""Generation-aware cancellation of superseded Scanner resources."""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any

from .kubernetes import ScannerClient
from .scanner_resource import TARGET_HASH_LABEL, scanner_name, target_hash


class CancellationError(RuntimeError):
    """Raised when existing Scanner state cannot be compared safely."""


@dataclass(frozen=True)
class CancellationResult:
    matched: int
    deleted: int


def cancel_event_scanner(
    scanner_client: ScannerClient,
    *,
    event_id: str,
) -> bool:
    """Delete the exact deterministic Scanner for a terminal event retry."""

    return scanner_client.delete(scanner_name(event_id))


def _resource_generation(resource: Mapping[str, Any]) -> int:
    spec = resource.get("spec")
    if not isinstance(spec, Mapping):
        raise CancellationError("Scanner resource has no authoritative spec")
    target = spec.get("target")
    if not isinstance(target, Mapping):
        raise CancellationError("Scanner resource has no authoritative target")
    generation = target.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise CancellationError("Scanner resource has an invalid generation")
    return generation


def _cancel_matching_scanners(
    scanner_client: ScannerClient,
    *,
    target_id: str,
    generation_matches: Callable[[int], bool],
    exclude_names: Collection[str] = (),
) -> CancellationResult:
    opaque_target_hash = target_hash(target_id)
    resources = scanner_client.list_for_target_hash(opaque_target_hash)

    candidates: list[str] = []
    matched = 0
    for resource in resources:
        if not isinstance(resource, Mapping):
            raise CancellationError("Kubernetes returned a non-object Scanner")
        metadata = resource.get("metadata")
        if not isinstance(metadata, Mapping):
            raise CancellationError("Scanner resource has no metadata")
        labels = metadata.get("labels")
        if not isinstance(labels, Mapping):
            raise CancellationError("Scanner resource has no labels")
        if labels.get(TARGET_HASH_LABEL) != opaque_target_hash:
            # Defend against a client or API that did not honor the selector.
            continue
        matched += 1
        if not generation_matches(_resource_generation(resource)):
            continue
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            raise CancellationError("cancellable Scanner resource has no name")
        if name in exclude_names:
            continue
        candidates.append(name)

    deleted = sum(1 for name in sorted(set(candidates)) if scanner_client.delete(name))
    return CancellationResult(matched=matched, deleted=deleted)


def cancel_older_scanners(
    scanner_client: ScannerClient,
    *,
    target_id: str,
    accepted_generation: int,
    exclude_names: Collection[str] = (),
) -> CancellationResult:
    """Delete only resources for the same target and a lower generation."""

    if (
        isinstance(accepted_generation, bool)
        or not isinstance(accepted_generation, int)
        or accepted_generation < 1
    ):
        raise ValueError("accepted_generation must be a positive integer")
    return _cancel_matching_scanners(
        scanner_client,
        target_id=target_id,
        generation_matches=lambda generation: generation < accepted_generation,
        exclude_names=exclude_names,
    )


def cancel_scanners_through_generation(
    scanner_client: ScannerClient,
    *,
    target_id: str,
    unsafe_generation: int,
    exclude_names: Collection[str] = (),
) -> CancellationResult:
    """Delete resources through a generation proven moved or inactive."""

    if (
        isinstance(unsafe_generation, bool)
        or not isinstance(unsafe_generation, int)
        or unsafe_generation < 1
    ):
        raise ValueError("unsafe_generation must be a positive integer")
    return _cancel_matching_scanners(
        scanner_client,
        target_id=target_id,
        generation_matches=lambda generation: generation <= unsafe_generation,
        exclude_names=exclude_names,
    )
