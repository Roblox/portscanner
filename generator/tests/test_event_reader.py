from __future__ import annotations

import json
import sys
import types
import unittest
from datetime import timedelta

from portscanner_generator.config import ConfigurationError, GeneratorConfig
from portscanner_generator.event_reader import (
    InvalidSqsEnvelope,
    MutableS3Object,
    UnexpectedS3Object,
    decode_sqs_s3_record,
    parse_shared_contract,
    read_target_event,
)
from portscanner_generator.handler import GeneratorServices, lambda_handler

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

    def test_shared_contract_receives_complete_document(self) -> None:
        captured: list[dict[str, object]] = []

        class SharedTargetEvent:
            @classmethod
            def from_dict(cls, value: dict[str, object]) -> object:
                captured.append(value)
                return object()

        module = types.ModuleType("portscanner_contracts")
        module.TargetEvent = SharedTargetEvent  # type: ignore[attr-defined]
        document = event_document()
        original = sys.modules.get("portscanner_contracts")
        sys.modules["portscanner_contracts"] = module
        try:
            parse_shared_contract(document)
        finally:
            if original is None:
                sys.modules.pop("portscanner_contracts", None)
            else:
                sys.modules["portscanner_contracts"] = original

        self.assertEqual(captured, [document])
        self.assertIn("provider_metadata", captured[0])
        self.assertIn("policy", captured[0])

    def test_shared_parse_target_event_is_preferred_when_available(self) -> None:
        captured: list[dict[str, object]] = []
        sentinel = object()

        module = types.ModuleType("portscanner_contracts")

        def parse_target_event(value: dict[str, object]) -> object:
            captured.append(value)
            return sentinel

        class LegacyTargetEvent:
            @classmethod
            def model_validate(cls, _: object) -> object:
                raise AssertionError("legacy parser must not be used")

        module.parse_target_event = parse_target_event  # type: ignore[attr-defined]
        module.TargetEvent = LegacyTargetEvent  # type: ignore[attr-defined]
        document = event_document()
        original = sys.modules.get("portscanner_contracts")
        sys.modules["portscanner_contracts"] = module
        try:
            parsed = parse_shared_contract(document)
        finally:
            if original is None:
                sys.modules.pop("portscanner_contracts", None)
            else:
                sys.modules["portscanner_contracts"] = original

        self.assertIs(parsed, sentinel)
        self.assertEqual(captured, [document])

    def test_removal_tombstone_is_owned_by_shared_event_parser(self) -> None:
        document = {"event_type": "target.removed", "event_id": "removal-event-hash"}
        expected = types.SimpleNamespace(
            event_type="target.removed",
            event_id="removal-event-hash",
        )
        module = types.ModuleType("portscanner_contracts")
        module.parse_target_event = lambda value: expected  # type: ignore[attr-defined]
        original = sys.modules.get("portscanner_contracts")
        sys.modules["portscanner_contracts"] = module
        try:
            event = parse_shared_contract(document)
        finally:
            if original is None:
                sys.modules.pop("portscanner_contracts", None)
            else:
                sys.modules["portscanner_contracts"] = original

        self.assertIs(event, expected)

    def test_wrong_source_and_malformed_json_are_acknowledged(self) -> None:
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

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(claims.acquired, [])
        self.assertEqual(scanner.created, [])

    def test_expired_event_is_deterministically_acknowledged(self) -> None:
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
        self.assertEqual(claims.acquired, [])
        self.assertEqual(scanner.created, [])

    def test_configuration_rejects_wrong_api_group(self) -> None:
        with self.assertRaises(ConfigurationError):
            config(api_group="other.example")

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
        self.assertFalse(claims.acquired)


if __name__ == "__main__":
    unittest.main()
