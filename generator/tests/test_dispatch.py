from __future__ import annotations

import copy
import json
import unittest
from datetime import timedelta
from ipaddress import IPv4Network

from portscanner_inventory.base import (
    OwnershipCheck as InventoryOwnershipCheck,
)
from portscanner_inventory.base import OwnershipVerdict

from portscanner_generator.config import GeneratorConfig
from portscanner_generator.handler import GeneratorServices, lambda_handler
from portscanner_generator.idempotency import ClaimDisposition, ClaimState
from portscanner_generator.kubernetes import (
    CreateResult,
    KubernetesScannerClient,
    ScannerConflictError,
)
from portscanner_generator.scanner_resource import scanner_name

from .fakes import (
    NOW,
    FakeClaimStore,
    FakeOwnershipService,
    FakeS3,
    FakeScannerClient,
    event_document,
    parse_test_event,
    scanner_item,
    sqs_record,
)


def config() -> GeneratorConfig:
    return GeneratorConfig(
        event_bucket="event-fixtures",
        event_prefix="target-events/",
        table_name="event-claims",
        cluster_name="scanner-cluster",
        namespace="scanner-system",
        aws_region="us-east-1",
        authorized_account_ids=("123456789012",),
    )


def services_for(
    document: dict[str, object],
    ownership: FakeOwnershipService,
    claims: FakeClaimStore,
    scanner: FakeScannerClient,
    *,
    runtime_config: GeneratorConfig | None = None,
) -> GeneratorServices:
    return GeneratorServices(
        config=runtime_config or config(),
        s3_client=FakeS3(json.dumps(document).encode()),
        claim_store=claims,  # type: ignore[arg-type]
        ownership_service=ownership,
        scanner_client_factory=lambda: scanner,
        event_parser=parse_test_event,
        clock=lambda: NOW,
    )


class DispatchTests(unittest.TestCase):
    def test_generator_denies_out_of_scope_target_before_ownership_or_creation(self) -> None:
        document = event_document()
        exact_name = scanner_name(str(document["event_id"]))
        target = document["target"]
        assert isinstance(target, dict)
        scanner = FakeScannerClient(
            items=[scanner_item(str(target["target_id"]), int(target["generation"]), exact_name)]
        )
        claims = FakeClaimStore()
        ownership = FakeOwnershipService("ACTIVE")
        scoped_config = GeneratorConfig(
            event_bucket="event-fixtures",
            event_prefix="target-events/",
            table_name="event-claims",
            cluster_name="scanner-cluster",
            namespace="scanner-system",
            aws_region="us-east-1",
            allowed_target_cidrs=(IPv4Network("198.51.100.0/24"),),
            authorized_account_ids=("123456789012",),
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(
                document,
                ownership,
                claims,
                scanner,
                runtime_config=scoped_config,
            ),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(ownership.calls, [])
        self.assertEqual(scanner.created, [])
        self.assertEqual(scanner.deleted, [])
        self.assertEqual(claims.acquired, [])
        self.assertEqual(claims.completed, [])

    def test_generator_denies_unauthorized_account_before_claim_or_target_apis(self) -> None:
        document = event_document()
        target = document["target"]
        assert isinstance(target, dict)
        target["scope_id"] = "222222222222"
        scanner = FakeScannerClient()
        claims = FakeClaimStore()
        ownership = FakeOwnershipService("ACTIVE")

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(document, ownership, claims, scanner),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(claims.acquired, [])
        self.assertEqual(claims.completed, [])
        self.assertEqual(ownership.calls, [])
        self.assertEqual(scanner.created, [])
        self.assertEqual(scanner.deleted, [])

    def test_active_exact_generation_dispatches_after_cancelling_older(self) -> None:
        document = event_document()
        target_id = document["target"]["target_id"]  # type: ignore[index]
        scanner = FakeScannerClient(items=[scanner_item(target_id, 2, "older-scan")])
        ownership = FakeOwnershipService("ACTIVE", current_generation=3)
        claims = FakeClaimStore()

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(document, ownership, claims, scanner),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner.deleted, ["older-scan"])
        self.assertEqual(len(scanner.created), 1)
        self.assertEqual(len(ownership.calls), 2)
        self.assertEqual(claims.completed[0]["state"], ClaimState.DISPATCHED)

    def test_stale_is_acknowledged_after_exact_retry_cleanup(self) -> None:
        document = event_document()
        target_id = document["target"]["target_id"]  # type: ignore[index]
        exact_name = scanner_name(document["event_id"])
        claims = FakeClaimStore()
        scanner_factory_calls = 0
        scanner = FakeScannerClient(
            items=[
                scanner_item(target_id, 3, exact_name),
                scanner_item(target_id, 3, "same-generation-sibling"),
                scanner_item(target_id, 4, "newer-scan"),
            ]
        )

        def scanner_factory() -> FakeScannerClient:
            nonlocal scanner_factory_calls
            scanner_factory_calls += 1
            return scanner

        class ProductionStaleOwnership:
            def validate_event(self, _event: object) -> InventoryOwnershipCheck:
                return InventoryOwnershipCheck(
                    OwnershipVerdict.STALE,
                    reason="generation",
                    current_generation=4,
                )

        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=ProductionStaleOwnership(),
            scanner_client_factory=scanner_factory,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner_factory_calls, 1)
        self.assertEqual(scanner.deleted, [exact_name, "same-generation-sibling"])
        self.assertEqual(
            [item["metadata"]["name"] for item in scanner.items],
            ["newer-scan"],
        )
        self.assertEqual(claims.completed[0]["state"], ClaimState.STALE)

    def test_policy_stale_cancels_same_generation_siblings_but_preserves_newer(self) -> None:
        document = event_document()
        target_id = document["target"]["target_id"]  # type: ignore[index]
        exact_name = scanner_name(document["event_id"])
        scanner = FakeScannerClient(
            items=[
                scanner_item(target_id, 3, exact_name),
                scanner_item(target_id, 3, "same-generation-sibling"),
                scanner_item(target_id, 4, "newer-scan"),
            ]
        )
        claims = FakeClaimStore()

        class PolicyStaleOwnership:
            def validate_event(self, _event: object) -> InventoryOwnershipCheck:
                return InventoryOwnershipCheck(
                    OwnershipVerdict.STALE,
                    reason="policy-or-lifecycle",
                    current_generation=3,
                )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(
                document,
                PolicyStaleOwnership(),
                claims,
                scanner,
            ),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner.deleted, [exact_name, "same-generation-sibling"])
        self.assertEqual(
            [item["metadata"]["name"] for item in scanner.items],
            ["newer-scan"],
        )
        self.assertEqual(claims.completed[0]["state"], ClaimState.STALE)

    def test_moved_and_inactive_cancel_without_dispatch(self) -> None:
        for verdict in ("MOVED", "INACTIVE"):
            with self.subTest(verdict=verdict):
                document = event_document()
                target_id = document["target"]["target_id"]  # type: ignore[index]
                exact_name = scanner_name(document["event_id"])
                scanner = FakeScannerClient(
                    items=[
                        scanner_item(target_id, 1, "older-scan"),
                        scanner_item(target_id, 3, exact_name),
                        scanner_item(target_id, 3, "same-generation-sibling"),
                        scanner_item(target_id, 4, "newer-scan"),
                    ]
                )
                claims = FakeClaimStore()
                response = lambda_handler(
                    {"Records": [sqs_record(document)]},
                    None,
                    services=services_for(
                        document,
                        FakeOwnershipService(verdict, current_generation=3),
                        claims,
                        scanner,
                    ),
                )

                self.assertEqual(response, {"batchItemFailures": []})
                self.assertEqual(
                    scanner.deleted,
                    [exact_name, "older-scan", "same-generation-sibling"],
                )
                self.assertEqual(
                    [item["metadata"]["name"] for item in scanner.items],
                    ["newer-scan"],
                )
                self.assertEqual(scanner.created, [])
                self.assertEqual(
                    claims.completed[0]["state"],
                    ClaimState.CANCELLED,
                )

    def test_unknown_is_retryable_and_creates_no_scanner(self) -> None:
        document = event_document()
        claims = FakeClaimStore()
        scanner = FakeScannerClient()
        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(
                document,
                FakeOwnershipService("UNKNOWN", current_generation=None),
                claims,
                scanner,
            ),
        )

        self.assertEqual(
            response,
            {"batchItemFailures": [{"itemIdentifier": "message-example-0001"}]},
        )
        self.assertEqual(scanner.created, [])
        self.assertEqual(scanner.listed_hashes, [])
        self.assertEqual(
            claims.retryable[0]["error_code"],
            "ownership_unknown",
        )

    def test_partial_batch_marks_only_retryable_message(self) -> None:
        class SequencedOwnership:
            def __init__(self) -> None:
                self.states = iter(("UNKNOWN", "STALE"))

            def validate_event(self, event: object) -> dict[str, object]:
                generation = event.target.generation  # type: ignore[attr-defined]
                return {
                    "state": next(self.states),
                    "requested_generation": generation,
                    "current_generation": generation,
                }

        document = event_document()
        claims = FakeClaimStore()
        scanner = FakeScannerClient()
        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=SequencedOwnership(),  # type: ignore[arg-type]
            scanner_client_factory=lambda: scanner,
            event_parser=parse_test_event,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {
                "Records": [
                    sqs_record(document, message_id="message-retry"),
                    sqs_record(document, message_id="message-ack"),
                ]
            },
            None,
            services=services,
        )

        self.assertEqual(
            response,
            {"batchItemFailures": [{"itemIdentifier": "message-retry"}]},
        )
        self.assertEqual(scanner.created, [])

    def test_final_ownership_recheck_can_stop_dispatch(self) -> None:
        class MovingOwnership:
            def __init__(self) -> None:
                self.states = iter(("ACTIVE", "MOVED"))

            def validate_event(self, event: object) -> dict[str, object]:
                generation = event.target.generation  # type: ignore[attr-defined]
                return {
                    "state": next(self.states),
                    "requested_generation": generation,
                    "current_generation": generation,
                }

        document = event_document()
        claims = FakeClaimStore()
        target_id = document["target"]["target_id"]  # type: ignore[index]
        exact_name = scanner_name(document["event_id"])
        scanner = FakeScannerClient(items=[scanner_item(target_id, 3, exact_name)])
        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=MovingOwnership(),  # type: ignore[arg-type]
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
        self.assertEqual(scanner.created, [])
        self.assertEqual(scanner.deleted, [exact_name])
        self.assertEqual(claims.completed[0]["state"], ClaimState.CANCELLED)

    def test_deadline_is_rechecked_immediately_before_create(self) -> None:
        deadline = NOW + timedelta(seconds=1)
        document = event_document(
            deadline_at=deadline,
            not_after=NOW + timedelta(minutes=30),
        )
        target_id = document["target"]["target_id"]  # type: ignore[index]
        exact_name = scanner_name(document["event_id"])
        scanner = FakeScannerClient(items=[scanner_item(target_id, 3, exact_name)])
        claims = FakeClaimStore()
        times = iter((NOW, deadline, deadline))
        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("ACTIVE"),
            scanner_client_factory=lambda: scanner,
            event_parser=parse_test_event,
            clock=lambda: next(times),
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner.created, [])
        self.assertEqual(scanner.deleted, [exact_name])
        self.assertEqual(claims.completed[0]["state"], ClaimState.EXPIRED)

    def test_active_generation_mismatch_fails_closed(self) -> None:
        cases = (
            (4, False),
            (2, True),
        )
        for current_generation, retryable in cases:
            with self.subTest(current_generation=current_generation):
                document = event_document()
                claims = FakeClaimStore()
                scanner = FakeScannerClient()
                response = lambda_handler(
                    {"Records": [sqs_record(document)]},
                    None,
                    services=services_for(
                        document,
                        FakeOwnershipService(
                            "ACTIVE",
                            current_generation=current_generation,
                        ),
                        claims,
                        scanner,
                    ),
                )
                self.assertEqual(bool(response["batchItemFailures"]), retryable)
                self.assertEqual(scanner.created, [])

    def test_removed_event_cancels_lower_generation_even_when_stale(self) -> None:
        document = event_document(event_type="target.removed")
        target_id = document["target"]["target_id"]  # type: ignore[index]
        exact_name = scanner_name(document["event_id"])
        scanner = FakeScannerClient(
            items=[
                scanner_item(target_id, 2, "older-scan"),
                scanner_item(target_id, 3, exact_name),
            ]
        )
        claims = FakeClaimStore()

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(
                document,
                FakeOwnershipService("STALE", current_generation=4),
                claims,
                scanner,
            ),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner.deleted, [exact_name, "older-scan"])
        self.assertEqual(scanner.created, [])
        self.assertEqual(claims.completed[0]["state"], ClaimState.REMOVED)

    def test_shared_removal_event_never_creates_scanner_resource(self) -> None:
        from portscanner_contracts import (
            AddressFamily,
            AwsContext,
            AwsTags,
            CloudProvider,
            SourceObservation,
            Target,
            TargetEventType,
            TargetRemoval,
            TransportProtocol,
        )

        target = Target.create(
            provider=CloudProvider.AWS,
            scope_id="123456789012",
            location="us-east-1",
            resource_id="eni-0123456789abcdef0",
            private_address="10.0.0.10",
            public_address="198.51.100.25",
            address_family=AddressFamily.IPV4,
            transport=TransportProtocol.TCP,
            generation=4,
        )
        source = SourceObservation.create(
            source_event_name="AwsConfigSnapshot",
            source_event_id="source-event-removal",
            source_request_id="source-request-removal",
            event_time=NOW - timedelta(minutes=2),
            observed_at=NOW - timedelta(minutes=1),
            collected_at=NOW - timedelta(seconds=30),
        )
        context = AwsContext(
            account_id=target.scope_id,
            region=target.location,
            network_interface_id=target.resource_id,
            private_ip=target.private_address,
            public_ip=target.public_address,
            instance_id="i-0123456789abcdef0",
            security_group_ids=("sg-0123456789abcdef0",),
            policy_fingerprint="4" * 64,
            candidate_tcp_port_ranges=(),
            source_event_name=source.source_event_name,
            source_event_id=source.source_event_id,
            source_request_id=source.source_request_id,
            tags=AwsTags(),
        )
        removal = TargetRemoval.create(
            schema_version="1.0",
            event_type=TargetEventType.TARGET_REMOVED,
            target=target,
            source=source,
            aws_context=context,
            removed_at=NOW,
        )
        document = removal.to_dict()
        exact_name = scanner_name(removal.event_id)
        scanner = FakeScannerClient(
            items=[
                scanner_item(target.target_id, 3, "older-scan"),
                scanner_item(target.target_id, 4, exact_name),
            ]
        )
        claims = FakeClaimStore()
        services = GeneratorServices(
            config=config(),
            s3_client=FakeS3(json.dumps(document).encode()),
            claim_store=claims,  # type: ignore[arg-type]
            ownership_service=FakeOwnershipService("STALE", current_generation=5),
            scanner_client_factory=lambda: scanner,
            clock=lambda: NOW,
        )

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services,
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(scanner.deleted, [exact_name, "older-scan"])
        self.assertEqual(scanner.created, [])
        self.assertEqual(claims.completed[0]["state"], ClaimState.REMOVED)

    def test_kubernetes_duplicate_is_finalized_as_dispatched(self) -> None:
        document = event_document()
        scanner = FakeScannerClient(create_result=CreateResult.ALREADY_EXISTS)
        claims = FakeClaimStore()

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(
                document,
                FakeOwnershipService("ACTIVE"),
                claims,
                scanner,
            ),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(claims.completed[0]["state"], ClaimState.DISPATCHED)

    def test_terminal_claim_duplicate_skips_ownership_and_kubernetes(self) -> None:
        document = event_document()
        ownership = FakeOwnershipService("ACTIVE")
        scanner = FakeScannerClient()
        claims = FakeClaimStore(ClaimDisposition.DUPLICATE)

        response = lambda_handler(
            {"Records": [sqs_record(document)]},
            None,
            services=services_for(document, ownership, claims, scanner),
        )

        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(ownership.calls, [])
        self.assertEqual(scanner.created, [])

    def test_raw_kubernetes_409_maps_to_already_exists(self) -> None:
        class Conflict(Exception):
            status = 409

        class CustomObjectsApi:
            def __init__(self, existing: dict[str, object]) -> None:
                self.existing = existing
                self.gets = 0

            def create_namespaced_custom_object(self, **_: object) -> None:
                raise Conflict()

            def get_namespaced_custom_object(self, **_: object) -> dict[str, object]:
                self.gets += 1
                return self.existing

        body = {
            "metadata": {
                "name": "scan-fixture",
                "labels": {"immutable.example/event": "same"},
            },
            "spec": {"eventId": "event-fixture"},
        }
        defaulted = copy.deepcopy(body)
        defaulted["spec"] = {
            **copy.deepcopy(body["spec"]),
            "retryLimit": 0,
            "ttlSecondsAfterFinished": 3600,
        }
        api = CustomObjectsApi(defaulted)
        client = KubernetesScannerClient(api, config())
        result = client.create(body)

        self.assertIs(result, CreateResult.ALREADY_EXISTS)
        self.assertEqual(api.gets, 1)

    def test_kubernetes_409_rejects_incompatible_or_terminal_existing_scanner(self) -> None:
        class Conflict(Exception):
            status = 409

        body = {
            "metadata": {
                "name": "scan-fixture",
                "labels": {"immutable.example/event": "same"},
            },
            "spec": {"eventId": "event-fixture"},
        }
        cases = {
            "spec": {
                **copy.deepcopy(body),
                "spec": {"eventId": "different"},
            },
            "labels": {
                **copy.deepcopy(body),
                "metadata": {
                    "name": "scan-fixture",
                    "labels": {"immutable.example/event": "different"},
                },
            },
            "deleting": {
                **copy.deepcopy(body),
                "metadata": {
                    **copy.deepcopy(body["metadata"]),
                    "deletionTimestamp": "2030-01-02T03:04:05Z",
                },
            },
            "cancelled": {
                **copy.deepcopy(body),
                "status": {"outcome": "Cancelled"},
            },
        }

        class CustomObjectsApi:
            def __init__(self, existing: dict[str, object]) -> None:
                self.existing = existing

            def create_namespaced_custom_object(self, **_: object) -> None:
                raise Conflict()

            def get_namespaced_custom_object(self, **_: object) -> dict[str, object]:
                return self.existing

        for name, existing in cases.items():
            with self.subTest(name=name):
                client = KubernetesScannerClient(CustomObjectsApi(existing), config())
                with self.assertRaises(ScannerConflictError):
                    client.create(body)

    def test_logs_hashes_without_raw_target_or_address(self) -> None:
        document = event_document()
        scanner = FakeScannerClient()
        claims = FakeClaimStore()
        target_id = document["target"]["target_id"]  # type: ignore[index]
        address = document["target"]["address"]  # type: ignore[index]

        with self.assertLogs(
            "portscanner_generator.handler",
            level="INFO",
        ) as captured:
            lambda_handler(
                {"Records": [sqs_record(document)]},
                None,
                services=services_for(
                    document,
                    FakeOwnershipService("ACTIVE"),
                    claims,
                    scanner,
                ),
            )

        logs = "\n".join(captured.output)
        self.assertNotIn(target_id, logs)
        self.assertNotIn(address, logs)
        self.assertIn('"event_hash"', logs)
        self.assertIn('"trace_hash"', logs)
        self.assertIn('"verdict":"ACTIVE"', logs)


if __name__ == "__main__":
    unittest.main()
