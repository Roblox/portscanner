from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from portscanner_inventory.aws.session import AwsClientFactory


class FakeSts:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def assume_role(self, **request: Any) -> dict[str, Any]:
        self.requests.append(request)
        return {
            "Credentials": {
                "AccessKeyId": "synthetic-access-key",
                "SecretAccessKey": "synthetic-secret-key",
                "SessionToken": "synthetic-session-token",
                "Expiration": datetime.now(UTC) + timedelta(minutes=15),
            }
        }


class FakeSession:
    def __init__(self) -> None:
        self.sts = FakeSts()
        self.requests: list[tuple[str, str | None, dict[str, Any]]] = []

    def client(self, service: str, region_name: str | None = None, **credentials: Any) -> Any:
        self.requests.append((service, region_name, credentials))
        if service == "sts":
            return self.sts
        return {"service": service, "region": region_name, "credentials": credentials}


def test_local_account_bypasses_member_role_assumption() -> None:
    session = FakeSession()
    factory = AwsClientFactory(
        session,
        role_arn_template="arn:aws:iam::{account_id}:role/collector",
        external_id="synthetic-external-id",
        local_account_id="123456789012",
    )

    client = factory.client("ec2", account_id="123456789012", region="us-east-1")

    assert client["credentials"] == {}
    assert session.sts.requests == []


def test_member_account_uses_configured_role_template() -> None:
    session = FakeSession()
    remote_account = "000000000000"
    role_template = "arn:aws:iam::{account_id}:role/collector"
    expected_role = role_template.format(account_id=remote_account)
    factory = AwsClientFactory(
        session,
        role_arn_template=role_template,
        external_id="synthetic-external-id",
        local_account_id="123456789012",
    )

    client = factory.client("ec2", account_id=remote_account, region="us-east-1")

    assert client["credentials"]["aws_session_token"] == "synthetic-session-token"
    assert session.sts.requests == [
        {
            "RoleArn": expected_role,
            "RoleSessionName": "portscanner-inventory",
            "DurationSeconds": 900,
            "ExternalId": "synthetic-external-id",
        }
    ]
