from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote_plus

import pytest
from portscanner_contracts import ScanReason, TargetRemoval, parse_target_event

from portscanner_inventory.aws.signals import parse_signal
from portscanner_inventory.base import CandidatePorts, Resolution, SnapshotScope
from portscanner_inventory.config import Settings
from portscanner_inventory.events import (
    build_removal_event,
    build_target_event,
    event_json,
    snapshot_source,
)
from portscanner_inventory.handlers.outbox import dispatch_record
from portscanner_inventory.handlers.outbox import lambda_handler as outbox_lambda
from portscanner_inventory.handlers.rescan import emit_coverage, schedule_bucket
from portscanner_inventory.handlers.signals import lambda_handler as signal_lambda
from portscanner_inventory.handlers.signals import process_signal
from portscanner_inventory.state import DynamoStateStore

from .helpers import ACCOUNT_ID, REGION, AwsError, FakeDynamo, normalized_target, permission

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
PRIORITY_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/priority"
COVERAGE_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/coverage"
TARGET_EVENT_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/target-events"


def _signal_event() -> dict[str, Any]:
    return {
        "id": "bridge-event-id",
        "source": "aws.ec2",
        "detail-type": "AWS API Call via CloudTrail",
        "account": ACCOUNT_ID,
        "region": REGION,
        "time": "2026-01-02T03:04:05Z",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "ModifyNetworkInterfaceAttribute",
            "eventID": "cloudtrail-event-id",
            "requestID": "request-id",
            "requestParameters": {
                "networkInterfaceId": "eni-aaaaaaaa",
                "groupSet": {"items": [{"groupId": "sg-11111111"}]},
            },
        },
    }


def test_signal_processing_deduplicates_and_reconciles_resolved_target() -> None:
    client = FakeDynamo()
    state = DynamoStateStore(client, "inventory")
    hint = parse_signal(_signal_event())
    assert hint is not None
    target = normalized_target().with_signal(
        event_name=hint.event_name,
        event_id=hint.event_id,
        request_id=hint.request_id,
        event_time=hint.event_time,
        candidate_ports=CandidatePorts.full(),
    )

    class Resolver:
        def resolve(self, _hint):
            return Resolution(targets=(target,))

    class Ownership:
        def validate(self, *_args):
            raise AssertionError("resolved target should not require removal validation")

    first = process_signal(
        _signal_event(),
        state,
        Resolver(),
        Ownership(),
        now=NOW,
        dedupe_seconds=60,
    )
    duplicate = process_signal(
        _signal_event(),
        state,
        Resolver(),
        Ownership(),
        now=NOW,
        dedupe_seconds=60,
    )

    assert first == {"status": "processed", "events": 1, "targets": 1}
    assert duplicate == {"status": "duplicate", "events": 0}


def test_signal_lambda_returns_partial_sqs_batch_failures() -> None:
    records = [
        {"messageId": "one", "body": json.dumps({"ok": True})},
        {"messageId": "two", "body": json.dumps({"ok": False})},
    ]

    def processor(value):
        if not value["ok"]:
            raise RuntimeError("synthetic failure")

    response = signal_lambda({"Records": records}, None, processor=processor)

    assert response == {"batchItemFailures": [{"itemIdentifier": "two"}]}


class S3:
    def __init__(
        self,
        *,
        conflict: bool = False,
        matching_head: bool = True,
        head_uses_metadata: bool = True,
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self.head_requests: list[dict[str, Any]] = []
        self.conflict = conflict
        self.matching_head = matching_head
        self.head_uses_metadata = head_uses_metadata
        self.etag: str | None = None
        self.version_id = "version-example"

    def put_object(self, **request: Any) -> dict[str, str]:
        self.requests.append(request)
        self.etag = hashlib.md5(request["Body"], usedforsecurity=False).hexdigest()
        if self.conflict:
            raise AwsError("PreconditionFailed")
        return {"ETag": f'"{self.etag}"', "VersionId": self.version_id}

    def head_object(self, **request: Any) -> dict[str, Any]:
        self.head_requests.append(request)
        assert self.etag is not None
        response: dict[str, Any] = {
            "ETag": f'"{self.etag if self.matching_head else "0" * 32}"',
            "VersionId": self.version_id,
        }
        if self.head_uses_metadata:
            expected = self.requests[-1]["Metadata"]["payload-sha256"]
            response["Metadata"] = {"payload-sha256": expected if self.matching_head else "0" * 64}
        return response


class SQS:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.requests: list[dict[str, str]] = []
        self.fail_on_call = fail_on_call

    def send_message(self, **request: str) -> None:
        self.requests.append(request)
        if self.fail_on_call == len(self.requests):
            raise RuntimeError("synthetic SQS failure")


def _outbox_record(event: Any, *, record_id: str = "stream-record") -> dict[str, Any]:
    return {
        "eventID": record_id,
        "eventName": "INSERT",
        "dynamodb": {
            "NewImage": {
                "entity": {"S": "outbox"},
                "event_id": {"S": event.event_id},
                "event_json": {"S": event_json(event)},
                "account_id": {"S": event.aws_context.account_id},
                "region": {"S": event.aws_context.region},
            }
        },
    }


def _work_event(reason: ScanReason) -> Any:
    scope = SnapshotScope(source="aws-config", name="example-aggregator")
    current = normalized_target()
    previous = None
    if reason is ScanReason.POLICY_CHANGE:
        previous = current
        current = normalized_target(permissions={"sg-11111111": [permission(80, 80)]})
    elif reason is ScanReason.TARGET_CHANGE:
        previous = current
        current = normalized_target(public_ip="203.0.113.20")
    return build_target_event(
        current,
        2 if previous is not None else 1,
        source=snapshot_source(scope, NOW),
        collected_at=NOW,
        previous=previous,
        reason=reason,
    )


def _removal_event() -> TargetRemoval:
    scope = SnapshotScope(source="aws-config", name="example-aggregator")
    return build_removal_event(
        normalized_target(),
        2,
        source=snapshot_source(scope, NOW),
        collected_at=NOW,
    )


def _dispatch(record: dict[str, Any], s3: S3, sqs: SQS) -> bool:
    return dispatch_record(
        record,
        s3,
        sqs,
        bucket="events",
        priority_queue_url=PRIORITY_QUEUE_URL,
        coverage_queue_url=COVERAGE_QUEUE_URL,
        target_event_queue_url=TARGET_EVENT_QUEUE_URL,
    )


def _decode_generator_style_notification(message_body: str) -> tuple[str, str, str, str]:
    envelope = json.loads(message_body)
    assert isinstance(envelope, dict)
    assert len(envelope["Records"]) == 1
    notification = envelope["Records"][0]
    assert notification["eventSource"] == "aws:s3"
    assert notification["eventName"].startswith("ObjectCreated:")
    object_data = notification["s3"]["object"]
    return (
        notification["s3"]["bucket"]["name"],
        unquote_plus(object_data["key"]),
        object_data["eTag"],
        object_data["versionId"],
    )


def test_outbox_dispatch_persists_hash_and_sends_s3_notifications() -> None:
    dynamo = FakeDynamo()
    state = DynamoStateStore(dynamo, "inventory")
    scope = SnapshotScope(source="aws-config", name="example-aggregator")
    result = state.reconcile(
        normalized_target(),
        source=snapshot_source(scope, NOW),
        now=NOW,
    )
    assert result.event is not None
    outbox = next(item for (pk, _sk), item in dynamo.items.items() if pk.startswith("OUTBOX#"))
    record = {
        "eventName": "INSERT",
        "dynamodb": {"NewImage": outbox},
    }
    s3 = S3()
    sqs = SQS()

    assert _dispatch(record, s3, sqs)
    request = s3.requests[0]
    assert request["IfNoneMatch"] == "*"
    assert request["Key"] == (
        f"target-events/aws/{ACCOUNT_ID}/{REGION}/{result.event.event_id}.json"
    )
    assert request["Metadata"]["payload-sha256"] == hashlib.sha256(request["Body"]).hexdigest()
    assert parse_target_event(request["Body"]).event_id == result.event.event_id

    assert [request["QueueUrl"] for request in sqs.requests] == [
        TARGET_EVENT_QUEUE_URL,
        PRIORITY_QUEUE_URL,
    ]
    expected_reference = (
        "events",
        request["Key"],
        s3.etag,
        s3.version_id,
    )
    assert _decode_generator_style_notification(sqs.requests[0]["MessageBody"]) == (
        expected_reference
    )
    assert sqs.requests[0]["MessageBody"] == sqs.requests[1]["MessageBody"]
    notification = json.loads(sqs.requests[0]["MessageBody"])
    assert "schema_version" not in notification
    assert "aws_context" not in notification


@pytest.mark.parametrize(
    ("event", "routed_queue"),
    [
        (_work_event(ScanReason.NEW_TARGET), PRIORITY_QUEUE_URL),
        (_work_event(ScanReason.TARGET_CHANGE), PRIORITY_QUEUE_URL),
        (_work_event(ScanReason.POLICY_CHANGE), PRIORITY_QUEUE_URL),
        (_work_event(ScanReason.MANUAL), PRIORITY_QUEUE_URL),
        (_work_event(ScanReason.COVERAGE), COVERAGE_QUEUE_URL),
        (_removal_event(), PRIORITY_QUEUE_URL),
    ],
    ids=["new", "target-change", "policy", "manual", "coverage", "removal"],
)
def test_outbox_routes_every_reason(
    event: Any,
    routed_queue: str,
) -> None:
    s3 = S3()
    sqs = SQS()

    assert _dispatch(_outbox_record(event), s3, sqs)

    assert [request["QueueUrl"] for request in sqs.requests] == [
        TARGET_EVENT_QUEUE_URL,
        routed_queue,
    ]


@pytest.mark.parametrize("head_uses_metadata", [True, False], ids=["sha256", "etag"])
def test_outbox_existing_object_retry_is_verified_before_notification(
    head_uses_metadata: bool,
) -> None:
    event = _work_event(ScanReason.NEW_TARGET)
    s3 = S3(conflict=True, head_uses_metadata=head_uses_metadata)
    sqs = SQS()

    assert _dispatch(_outbox_record(event), s3, sqs)

    assert len(s3.requests) == 1
    assert len(s3.head_requests) == 1
    assert len(sqs.requests) == 2


def test_outbox_rejects_mismatched_existing_object_without_notifying() -> None:
    event = _work_event(ScanReason.NEW_TARGET)
    s3 = S3(conflict=True, matching_head=False)
    sqs = SQS()

    with pytest.raises(ValueError, match="payload hash does not match"):
        _dispatch(_outbox_record(event), s3, sqs)

    assert sqs.requests == []


def test_outbox_notification_failure_returns_partial_batch_failure() -> None:
    records = [
        _outbox_record(_work_event(ScanReason.NEW_TARGET), record_id="one"),
        _outbox_record(_work_event(ScanReason.COVERAGE), record_id="two"),
    ]
    s3 = S3()
    sqs = SQS(fail_on_call=3)

    class Runtime:
        def process(self, record: dict[str, Any]) -> None:
            _dispatch(record, s3, sqs)

    response = outbox_lambda({"Records": records}, None, runtime=Runtime())

    assert response == {"batchItemFailures": [{"itemIdentifier": "two"}]}


def test_outbox_settings_require_all_exact_queue_environment_variables() -> None:
    settings = Settings.from_env(
        {
            "INVENTORY_TABLE": "inventory",
            "TARGET_EVENT_BUCKET": "events",
            "PRIORITY_QUEUE_URL": PRIORITY_QUEUE_URL,
            "COVERAGE_QUEUE_URL": COVERAGE_QUEUE_URL,
            "TARGET_EVENT_QUEUE_URL": TARGET_EVENT_QUEUE_URL,
        }
    )

    settings.validate_outbox()
    assert settings.priority_queue_url == PRIORITY_QUEUE_URL
    assert settings.coverage_queue_url == COVERAGE_QUEUE_URL
    assert settings.target_event_queue_url == TARGET_EVENT_QUEUE_URL

    missing = Settings(state_table="inventory", event_bucket="events")
    with pytest.raises(ValueError, match=r"PRIORITY_QUEUE_URL.*COVERAGE_QUEUE_URL"):
        missing.validate_outbox()


def test_rescan_bucket_and_events_are_deterministic() -> None:
    client = FakeDynamo()
    state = DynamoStateStore(client, "inventory")
    scope = SnapshotScope(source="aws-config", name="example-aggregator")
    state.reconcile(
        normalized_target(),
        source=snapshot_source(scope, NOW),
        now=NOW,
    )

    first = emit_coverage(state, now=NOW, bucket_seconds=3600)
    second = emit_coverage(state, now=NOW, bucket_seconds=3600)
    bucket, start = schedule_bucket(NOW, 3600)

    assert bucket > 0
    assert start.minute == start.second == 0
    assert first["events"] == 1
    assert second["events"] == 0
