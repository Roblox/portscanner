"""Direct EC2 paginated snapshot backend for accounts without AWS Config."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from portscanner_inventory.aws.normalize import (
    NormalizedTarget,
    extract_security_group,
    normalize_network_interface,
)
from portscanner_inventory.base import (
    ScopeCompletion,
    SnapshotBatch,
    SnapshotScope,
    aws_error_code,
)


@dataclass(frozen=True, slots=True)
class _PageResult:
    values: tuple[Mapping[str, Any], ...]
    pages: int
    failure_code: str | None = None


class Ec2SnapshotBackend:
    def __init__(
        self,
        client: Any,
        *,
        account_id: str,
        region: str,
        allowed_tag_keys: Sequence[str] = (),
        allowed_interface_types: Sequence[str] = (),
        required_tag_key: str | None = None,
        required_tag_value: str | None = None,
        page_size: int = 500,
        max_pages: int = 1000,
    ) -> None:
        self._client = client
        self._scope = SnapshotScope(source="ec2", account_id=account_id, region=region)
        self._allowed_tag_keys = tuple(allowed_tag_keys)
        self._allowed_interface_types = tuple(allowed_interface_types)
        self._required_tag_key = required_tag_key
        self._required_tag_value = required_tag_value
        self._page_size = page_size
        self._max_pages = max_pages
        if not 5 <= page_size <= 1000:
            raise ValueError("EC2 page size must be within 5..1000")
        if not 1 <= max_pages <= 10_000:
            raise ValueError("EC2 max_pages must be within 1..10000")

    def _fetch(self, operation: str, result_key: str) -> _PageResult:
        values: list[Mapping[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        pages = 0
        while True:
            request: dict[str, Any] = {"MaxResults": self._page_size}
            if token:
                request["NextToken"] = token
            try:
                response = getattr(self._client, operation)(**request)
            except Exception as error:
                return _PageResult(tuple(values), pages, aws_error_code(error))
            pages += 1
            values.extend(
                item for item in response.get(result_key, ()) if isinstance(item, Mapping)
            )
            next_token = response.get("NextToken")
            if not next_token:
                return _PageResult(tuple(values), pages)
            next_value = str(next_token)
            if next_value in seen_tokens:
                return _PageResult(tuple(values), pages, "pagination-token-repeated")
            if pages >= self._max_pages:
                return _PageResult(tuple(values), pages, "pagination-page-limit")
            seen_tokens.add(next_value)
            token = next_value

    def collect(self) -> SnapshotBatch:
        group_fetch = self._fetch("describe_security_groups", "SecurityGroups")
        eni_fetch = self._fetch("describe_network_interfaces", "NetworkInterfaces")
        instance_fetch = self._fetch("describe_instances", "Reservations")
        pages = group_fetch.pages + eni_fetch.pages + instance_fetch.pages
        failure_code = (
            group_fetch.failure_code or eni_fetch.failure_code or instance_fetch.failure_code
        )
        malformed = 0

        security_groups: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for value in group_fetch.values:
            try:
                group_id, permissions = extract_security_group(value)
                security_groups[group_id] = permissions
            except (TypeError, ValueError):
                malformed += 1

        instance_states: dict[str, str] = {}
        for reservation in instance_fetch.values:
            for instance in reservation.get("Instances", ()):
                if not isinstance(instance, Mapping) or not instance.get("InstanceId"):
                    malformed += 1
                    continue
                state = instance.get("State")
                if not isinstance(state, Mapping) or not state.get("Name"):
                    malformed += 1
                    continue
                instance_states[str(instance["InstanceId"])] = str(state["Name"]).lower()

        normalized: dict[str, NormalizedTarget] = {}
        for value in eni_fetch.values:
            try:
                attachment = value.get("Attachment")
                instance_id = (
                    str(attachment["InstanceId"])
                    if isinstance(attachment, Mapping) and attachment.get("InstanceId")
                    else None
                )
                for target in normalize_network_interface(
                    value,
                    account_id=self._scope.account_id or "",
                    region=self._scope.region or "",
                    security_groups=security_groups,
                    allowed_tag_keys=self._allowed_tag_keys,
                    instance_state=instance_states.get(instance_id or ""),
                    allowed_interface_types=self._allowed_interface_types,
                    required_tag_key=self._required_tag_key,
                    required_tag_value=self._required_tag_value,
                ):
                    normalized[target.target_id] = target
            except (KeyError, TypeError, ValueError):
                malformed += 1

        if failure_code:
            completion = ScopeCompletion.PARTIAL if normalized else ScopeCompletion.FAILED
        elif malformed:
            completion = ScopeCompletion.PARTIAL
            failure_code = "malformed-record"
        else:
            completion = ScopeCompletion.COMPLETE
        return SnapshotBatch(
            scope=self._scope,
            targets=tuple(normalized[key] for key in sorted(normalized)),
            completion=completion,
            pages=pages,
            malformed_records=malformed,
            failure_code=failure_code,
        )
