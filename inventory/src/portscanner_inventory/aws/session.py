"""Credential-safe AWS client construction with optional role assumption."""

from __future__ import annotations

import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")


class AwsClientFactory:
    """Create and cache clients without exposing credential material."""

    def __init__(
        self,
        session: Any | None = None,
        *,
        role_arn_template: str | None = None,
        external_id: str | None = None,
        local_account_id: str | None = None,
    ) -> None:
        if session is None:
            import boto3

            session = boto3.Session()
        self._session = session
        self._role_arn_template = role_arn_template
        self._external_id = external_id
        if local_account_id is not None and not _ACCOUNT_RE.fullmatch(local_account_id):
            raise ValueError("invalid local_account_id")
        self._local_account_id = local_account_id
        self._clients: dict[
            tuple[str, str | None, str | None],
            tuple[Any, datetime | None],
        ] = {}
        self._lock = threading.Lock()

    def client(
        self,
        service: str,
        *,
        account_id: str | None = None,
        region: str | None = None,
    ) -> Any:
        if not re.fullmatch(r"[a-z0-9-]+", service):
            raise ValueError("invalid AWS service name")
        if account_id is not None and not _ACCOUNT_RE.fullmatch(account_id):
            raise ValueError("invalid account_id")
        if region is not None and not _REGION_RE.fullmatch(region):
            raise ValueError("invalid AWS region")
        if self._role_arn_template and account_id is None:
            raise ValueError("account_id is required when role assumption is configured")

        key = (service, account_id, region)
        with self._lock:
            cached = self._clients.get(key)
            if cached is not None:
                client, expires_at = cached
                if expires_at is None or expires_at > datetime.now(UTC) + timedelta(minutes=1):
                    return client
            client, expires_at = self._new_client(
                service,
                account_id=account_id,
                region=region,
            )
            self._clients[key] = (client, expires_at)
            return client

    def _new_client(
        self,
        service: str,
        *,
        account_id: str | None,
        region: str | None,
    ) -> tuple[Any, datetime | None]:
        if not self._role_arn_template or account_id == self._local_account_id:
            return self._session.client(service, region_name=region), None

        assert account_id is not None
        role_arn = self._role_arn_template.format(account_id=account_id)
        request: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": "portscanner-inventory",
            "DurationSeconds": 900,
        }
        if self._external_id:
            request["ExternalId"] = self._external_id
        response = self._session.client("sts", region_name=region).assume_role(**request)
        credentials = response["Credentials"]
        expiration = credentials.get("Expiration")
        expires_at = (
            expiration.astimezone(UTC)
            if isinstance(expiration, datetime) and expiration.tzinfo is not None
            else datetime.now(UTC) + timedelta(minutes=14)
        )
        return (
            self._session.client(
                service,
                region_name=region,
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            ),
            expires_at,
        )
