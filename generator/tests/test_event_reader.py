from __future__ import annotations

import json
import unittest
from datetime import timedelta

from portscanner_generator.config import ConfigurationError, GeneratorConfig
from portscanner_generator.event_reader import (
    InvalidSqsEnvelope,
    MutableS3Object,
    UnexpectedS3Object,
    decode_sqs_s3_record,
    read_target_event,
)
from portscanner_generator.handler import GeneratorServices, lambda_handler
from portscanner_generator.idempotency import ClaimState

from .fakes import (
    NOW,
    FakeClaimStore,
    FakeOwnershipService,
    FakeS3,
    FakeScannerClient,
    event_document,
    parse_test_event,
    sqs_record,
)


def config(**overrides: object) -> GeneratorConfig:
    values: dict[str, object] = {
        "event_bucket": "event-fixtures",
        "event_prefix": "target-events/",
        "table_name": "event-claims",
        "cluster_name": "scanner-cluster",
        "namespace": "scanner-system",
        "aws_region": "us-east-1",
        "authorized_account_ids": ("123456789012",),
    }
    values.update(overrides)
    return GeneratorConfig(**values)  # type: ignore[arg-type]


class EventReaderTests(unittest.TestCase):
    def test_decodes_sqs_s3_and_fetches_notified_immutable_object(self) -> None:
        document = event_document()
        content = json.dumps(document).encode()
        s3 = FakeS3(content)
        record = sqs_record(
            document,
            key="target-events/folder/event with space.json",
        )

        reference, event = read_target_event(
            record,
            s3,
            config(),
            parser=parse_test_event,
        )

        self.assertEqual(
            reference.key,
            "target-events/folder/event with space.json",
        )
        self.assertEqual(event.provider_metadata, {"fixture": "safe"})
        self.assertEqual(
            s3.calls,
            [
                {
                    "Bucket": "event-fixtures",
                    "Key": "target-events/folder/event with space.json",
                    "IfMatch": "fixture-etag",
                }
            ],
        )

    def test_versioned_notification_fetches_exact_version(self) -> None:
        document = event_document()
        s3 = FakeS3(json.dumps(document).encode())
        record = sqs_record(
            document,
            etag=None,
            version_id="version-example",
        )

        read_target_event(record, s3, config(), parser=parse_test_event)

        self.assertEqual(s3.calls[0]["VersionId"], "version-example")
        self.assertNotIn("IfMatch", s3.calls[0])

    def test_wrong_bucket_and_prefix_are_rejected_before_fetch(self) -> None:
        document = event_document()
        s3 = FakeS3(json.dumps(document).encode())
        with self.assertRaises(UnexpectedS3Object):
            decode_sqs_s3_record(
                sqs_record(document, bucket="other-fixtures"),
                config(),
            )
        with self.assertRaises(UnexpectedS3Object):
            decode_sqs_s3_record(
                sqs_record(document, key="target-events-foreign/event.json"),
                config(),
            )
        self.assertEqual(s3.calls, [])

    def test_requires_one_nested_s3_record(self) -> None:
        with self.assertRaises(InvalidSqsEnvelope):
            decode_sqs_s3_record(
                sqs_record(event_document(), nested_records=2),
                config(),
            )

    def test_requires_immutable_object_identity(self) -> None:
        with self.assertRaises(MutableS3Object):
            decode_sqs_s3_record(
                sqs_record(event_document(), etag=None),
                config(),
            )

    def test_wrong_source_and_malformed_json_are_redriven(self) -> None:
        malformed = sqs_record("{not-json")
        wrong_source = sqs_record(
            event_document(),
            bucket="other-fixtures",
            message_id="message-example-0002",
        )
        s3 = FakeS3(b"{not-json")
        claims = FakeClaimStore()
        scanner = FakeScannerClient()
        services = GeneratorServices(
            config=config(),
            s3_client=s3,
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("ACTIVE"),
            scanner_client_factory=lambda: scanner,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {"Records": [wrong_source, malformed]},
            None,
            services=services,
        )

        self.assertEqual(
            response,
            {
                "batchItemFailures": [
                    {"itemIdentifier": "message-example-0002"},
                    {"itemIdentifier": "message-example-0001"},
                ]
            },
        )
        self.assertEqual(claims.acquired, [])
        self.assertEqual(scanner.created, [])

    def test_expired_event_is_claimed_and_finalized_without_creation(self) -> None:
        document = event_document(not_after=NOW)
        s3 = FakeS3(json.dumps(document).encode())
        claims = FakeClaimStore()
        scanner = FakeScannerClient()
        services = GeneratorServices(
            config=config(),
            s3_client=s3,
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("ACTIVE"),
            scanner_client_factory=lambda: scanner,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(len(claims.acquired), 1)
        self.assertEqual(claims.completed[0]["state"], ClaimState.EXPIRED)
        self.assertEqual(scanner.created, [])

    def test_dispatch_deadline_is_finalized_after_claim_at_boundary(self) -> None:
        document = event_document(
            deadline_at=NOW,
            not_after=NOW + timedelta(minutes=30),
        )
        claims = FakeClaimStore()
        scanner = FakeScannerClient()
        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("ACTIVE"),
            scanner_client_factory=lambda: scanner,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(len(claims.acquired), 1)
        self.assertEqual(claims.completed[0]["state"], ClaimState.EXPIRED)
        self.assertEqual(scanner.created, [])

    def test_configuration_rejects_wrong_api_group(self) -> None:
        with self.assertRaises(ConfigurationError):
            config(api_group="other.example")

    def test_configuration_parses_canonical_cidrs_and_applies_denies_first(self) -> None:
        environment = {
            "TARGET_EVENT_BUCKET": "event-fixtures",
            "TARGET_EVENT_PREFIX": "target-events/",
            "IDEMPOTENCY_TABLE": "event-claims",
            "EKS_CLUSTER_NAME": "scanner-cluster",
            "K8S_NAMESPACE": "scanner-system",
            "AWS_REGION": "us-east-1",
            "AUTHORIZED_ACCOUNT_IDS": "222222222222,123456789012",
            "ALLOWED_TARGET_CIDRS": "203.0.113.0/24",
            "DENIED_TARGET_CIDRS": "203.0.113.10/32",
        }
        settings = GeneratorConfig.from_environment(environment)

        self.assertTrue(settings.target_allowed("203.0.113.11"))
        self.assertFalse(settings.target_allowed("203.0.113.10"))
        self.assertFalse(settings.target_allowed("198.51.100.1"))
        self.assertTrue(settings.account_allowed("123456789012"))
        self.assertFalse(settings.account_allowed("000000000000"))

        environment["ALLOWED_TARGET_CIDRS"] = "203.0.113.10/24"
        with self.assertRaisesRegex(ConfigurationError, "canonical IPv4"):
            GeneratorConfig.from_environment(environment)

        environment["ALLOWED_TARGET_CIDRS"] = "203.0.113.0/24"
        environment["AUTHORIZED_ACCOUNT_IDS"] = "not-an-account"
        with self.assertRaisesRegex(ConfigurationError, "12-digit"):
            GeneratorConfig.from_environment(environment)

    def test_not_after_boundary_includes_later_time(self) -> None:
        document = event_document(not_after=NOW - timedelta(microseconds=1))
        s3 = FakeS3(json.dumps(document).encode())
        claims = FakeClaimStore()
        services = GeneratorServices(
            config=config(),
            s3_client=s3,
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("ACTIVE"),
            scanner_client_factory=FakeScannerClient,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )
        result = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )
        self.assertEqual(result["batchItemFailures"], [])
        self.assertEqual(len(claims.acquired), 1)
        self.assertEqual(claims.completed[0]["state"], ClaimState.EXPIRED)


if __name__ == "__main__":
    unittest.main()
