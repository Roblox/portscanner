"""AWS Config aggregator snapshot backend."""

from __future__ import annotations

import json
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

PUBLIC_ENI_QUERY = """
SELECT
  accountId,
  awsRegion,
  resourceId,
  resourceType,
  configurationItemCaptureTime,
  configuration
WHERE
  resourceType = 'AWS::EC2::NetworkInterface'
  AND configuration.association.publicIp > '0.0.0.0'
""".strip()

SECURITY_GROUP_QUERY = """
SELECT
  accountId,
  awsRegion,
  resourceId,
  resourceType,
  configurationItemCaptureTime,
  configuration
WHERE
  resourceType = 'AWS::EC2::SecurityGroup'
""".strip()


@dataclass(frozen=True, slots=True)
class _Fetch:
    records: tuple[Mapping[str, Any], ...]
    pages: int
    malformed: int = 0
    failure_code: str | None = None


def _scope_filter(query: str, scope: SnapshotScope) -> str:
    filters: list[str] = []
    if scope.account_id:
        filters.append(f"accountId = '{scope.account_id}'")
    if scope.region:
        filters.append(f"awsRegion = '{scope.region}'")
    if not filters:
        return query
    return f"{query}\n  AND " + "\n  AND ".join(filters)


class ConfigSnapshotBackend:
    """Read a complete aggregator view before allowing absence to mean removal."""

    def __init__(
        self,
        client: Any,
        *,
        aggregator_name: str,
        scope: SnapshotScope | None = None,
        allowed_tag_keys: Sequence[str] = (),
        page_size: int = 100,
    ) -> None:
        self._client = client
        self._aggregator_name = aggregator_name
        self._scope = scope or SnapshotScope(source="aws-config", name=aggregator_name)
        self._allowed_tag_keys = tuple(allowed_tag_keys)
        self._page_size = page_size
        if self._scope.source != "aws-config":
            raise ValueError("Config backend requires an aws-config scope")
        if not 1 <= page_size <= 100:
            raise ValueError("Config page_size must be within 1..100")

    def fetch_records(self, expression: str) -> _Fetch:
        records: list[Mapping[str, Any]] = []
        token: str | None = None
        pages = 0
        malformed = 0
        while True:
            request: dict[str, Any] = {
                "Expression": _scope_filter(expression, self._scope),
                "ConfigurationAggregatorName": self._aggregator_name,
                "Limit": self._page_size,
            }
            if token:
                request["NextToken"] = token
            try:
                response = self._client.select_aggregate_resource_config(**request)
            except Exception as error:
                return _Fetch(
                    records=tuple(records),
                    pages=pages,
                    malformed=malformed,
                    failure_code=aws_error_code(error),
                )
            pages += 1
            for raw in response.get("Results", ()):
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except (TypeError, ValueError):
                    malformed += 1
                    continue
                if not isinstance(parsed, Mapping):
                    malformed += 1
                    continue
                records.append(parsed)
            next_token = response.get("NextToken")
            if not next_token:
                return _Fetch(tuple(records), pages, malformed)
            token = str(next_token)

    def collect(self) -> SnapshotBatch:
        group_fetch = self.fetch_records(SECURITY_GROUP_QUERY)
        eni_fetch = self.fetch_records(PUBLIC_ENI_QUERY)
        pages = group_fetch.pages + eni_fetch.pages
        malformed = group_fetch.malformed + eni_fetch.malformed
        failure_code = group_fetch.failure_code or eni_fetch.failure_code

        security_groups: dict[
            tuple[str, str, str],
            tuple[Mapping[str, Any], ...],
        ] = {}
        for record in group_fetch.records:
            try:
                account_id = str(record["accountId"])
                region = str(record["awsRegion"])
                group_id, permissions = extract_security_group(record)
                if not self._scope.includes(account_id, region):
                    raise ValueError("record outside requested scope")
                security_groups[(account_id, region, group_id)] = permissions
            except (KeyError, TypeError, ValueError):
                malformed += 1

        normalized: dict[str, NormalizedTarget] = {}
        for record in eni_fetch.records:
            try:
                account_id = str(record["accountId"])
                region = str(record["awsRegion"])
                if not self._scope.includes(account_id, region):
                    raise ValueError("record outside requested scope")
                configuration = record.get("configuration")
                if isinstance(configuration, str):
                    configuration = json.loads(configuration)
                if not isinstance(configuration, Mapping):
                    raise ValueError("invalid ENI configuration")
                raw_groups = (
                    configuration.get("groups")
                    or configuration.get("Groups")
                    or configuration.get("groupSet")
                    or ()
                )
                if isinstance(raw_groups, Mapping):
                    raw_groups = raw_groups.get("items") or ()
                group_ids = {
                    str(group.get("groupId") or group.get("GroupId") or "")
                    for group in raw_groups
                    if isinstance(group, Mapping)
                }
                attached = {
                    group_id: security_groups[(account_id, region, group_id)]
                    for group_id in group_ids
                }
                for target in normalize_network_interface(
                    record,
                    account_id=account_id,
                    region=region,
                    security_groups=attached,
                    allowed_tag_keys=self._allowed_tag_keys,
                ):
                    normalized[target.target_id] = target
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
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
