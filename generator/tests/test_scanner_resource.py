from __future__ import annotations

import unittest

from portscanner_generator.cancellation import (
    CancellationError,
    cancel_event_scanner,
    cancel_older_scanners,
    cancel_scanners_through_generation,
)
from portscanner_generator.config import GeneratorConfig
from portscanner_generator.kubernetes import KubernetesScannerClient
from portscanner_generator.scanner_resource import (
    READABLE_STATUS_ANNOTATION,
    TARGET_HASH_LABEL,
    build_scanner_resource,
    scanner_name,
    target_hash,
)

from .fakes import (
    FakeScannerClient,
    event_document,
    parse_test_event,
    scanner_item,
)


def config() -> GeneratorConfig:
    return GeneratorConfig(
        event_bucket="event-fixtures",
        event_prefix="target-events/",
        table_name="event-claims",
        cluster_name="scanner-cluster",
        namespace="scanner-system",
        aws_region="us-east-1",
    )


class ScannerResourceTests(unittest.TestCase):
    def test_resource_has_authoritative_v1alpha1_shape(self) -> None:
        event = parse_test_event(event_document(reason="target_change"))

        body = build_scanner_resource(
            event,
            namespace="scanner-system",
        )

        self.assertEqual(
            body["apiVersion"],
            "scanning.portscanner.io/v1alpha1",
        )
        self.assertEqual(body["kind"], "Scanner")
        self.assertEqual(
            body["metadata"]["annotations"][READABLE_STATUS_ANNOTATION],
            "Changed door",
        )
        spec = body["spec"]
        self.assertEqual(
            set(spec),
            {
                "target",
                "eventId",
                "directiveId",
                "traceId",
                "reason",
                "profile",
                "ports",
                "ranges",
                "priority",
                "deadline",
                "notAfter",
                "sourceTimestamps",
            },
        )
        self.assertEqual(
            spec["target"],
            {
                "address": "192.0.2.10",
                "targetId": "2" * 64,
                "provider": "aws",
                "scopeId": "123456789012",
                "location": "us-east-1",
                "resourceId": "eni-0123456789abcdef0",
                "privateAddress": "10.0.0.10",
                "generation": 3,
            },
        )
        self.assertEqual(spec["directiveId"], "3" * 64)
        self.assertEqual(spec["reason"], "target_change")
        self.assertEqual(spec["profile"], "fast-full-tcp")
        self.assertEqual(spec["ports"], [])
        self.assertEqual(spec["ranges"], [{"start": 1, "end": 65535}])
        self.assertEqual(spec["priority"], 100)
        self.assertEqual(
            set(spec["sourceTimestamps"]),
            {"eventAt", "observedAt"},
        )

    def test_reason_annotations_match_talk_labels(self) -> None:
        expected = {
            "new_target": "New door",
            "target_change": "Changed door",
            "policy_change": "Changed door",
            "coverage": "Known door",
            "manual": "Manual verification",
        }
        for reason, label in expected.items():
            with self.subTest(reason=reason):
                body = build_scanner_resource(
                    parse_test_event(event_document(reason=reason)),
                    namespace="scanner-system",
                )
                self.assertEqual(
                    body["metadata"]["annotations"][READABLE_STATUS_ANNOTATION],
                    label,
                )

    def test_labels_and_name_never_contain_raw_target_data(self) -> None:
        event = parse_test_event(event_document())
        body = build_scanner_resource(
            event,
            namespace="scanner-system",
        )
        labels = body["metadata"]["labels"]
        serialized_labels = " ".join(f"{key}={value}" for key, value in labels.items())

        self.assertNotIn(event.target.target_id, serialized_labels)
        self.assertNotIn(event.target.address, serialized_labels)
        self.assertEqual(
            labels[TARGET_HASH_LABEL],
            target_hash(event.target.target_id),
        )
        self.assertEqual(
            body["metadata"]["name"],
            scanner_name(event.event_id),
        )
        self.assertLessEqual(len(body["metadata"]["name"]), 63)

    def test_cancellation_deletes_only_lower_generations(self) -> None:
        event = parse_test_event(event_document())
        unrelated_target = "aws:example-scope:example-region:other-resource:address"
        scanner = FakeScannerClient(
            items=[
                scanner_item(event.target.target_id, 1, "generation-one"),
                scanner_item(event.target.target_id, 2, "generation-two"),
                scanner_item(event.target.target_id, 3, "generation-three"),
                scanner_item(event.target.target_id, 4, "generation-four"),
                scanner_item(unrelated_target, 1, "unrelated"),
            ]
        )

        result = cancel_older_scanners(
            scanner,
            target_id=event.target.target_id,
            accepted_generation=3,
        )

        self.assertEqual(
            scanner.deleted,
            ["generation-one", "generation-two"],
        )
        self.assertEqual(result.matched, 4)
        self.assertEqual(result.deleted, 2)
        self.assertEqual(
            scanner.listed_hashes,
            [target_hash(event.target.target_id)],
        )

    def test_terminal_retry_deletes_exact_event_scanner(self) -> None:
        event = parse_test_event(event_document())
        name = scanner_name(event.event_id)
        scanner = FakeScannerClient(
            items=[scanner_item(event.target.target_id, event.target.generation, name)]
        )

        deleted = cancel_event_scanner(scanner, event_id=event.event_id)

        self.assertTrue(deleted)
        self.assertEqual(scanner.deleted, [name])

    def test_unsafe_generation_cancellation_includes_siblings_not_newer_work(self) -> None:
        event = parse_test_event(event_document())
        scanner = FakeScannerClient(
            items=[
                scanner_item(event.target.target_id, 2, "older"),
                scanner_item(event.target.target_id, 3, "sibling-a"),
                scanner_item(event.target.target_id, 3, "sibling-b"),
                scanner_item(event.target.target_id, 4, "newer"),
            ]
        )

        result = cancel_scanners_through_generation(
            scanner,
            target_id=event.target.target_id,
            unsafe_generation=3,
        )

        self.assertEqual(scanner.deleted, ["older", "sibling-a", "sibling-b"])
        self.assertEqual(result.matched, 4)
        self.assertEqual(result.deleted, 3)

    def test_malformed_matching_resource_fails_closed(self) -> None:
        event = parse_test_event(event_document())
        scanner = FakeScannerClient(
            items=[
                {
                    "metadata": {
                        "name": "malformed",
                        "labels": {TARGET_HASH_LABEL: target_hash(event.target.target_id)},
                    },
                    "spec": {"target": {"generation": "2"}},
                }
            ]
        )

        with self.assertRaises(CancellationError):
            cancel_older_scanners(
                scanner,
                target_id=event.target.target_id,
                accepted_generation=3,
            )
        self.assertEqual(scanner.deleted, [])

    def test_kubernetes_list_uses_only_hashed_target_selector(self) -> None:
        class CustomObjectsApi:
            def __init__(self) -> None:
                self.request: dict[str, object] | None = None

            def list_namespaced_custom_object(
                self,
                **request: object,
            ) -> dict[str, list[object]]:
                self.request = request
                return {"items": []}

        api = CustomObjectsApi()
        client = KubernetesScannerClient(api, config())
        opaque_hash = target_hash("target-example")
        client.list_for_target_hash(opaque_hash)

        self.assertEqual(
            api.request["label_selector"],  # type: ignore[index]
            f"{TARGET_HASH_LABEL}={opaque_hash}",
        )
        self.assertNotIn("target-example", str(api.request))


if __name__ == "__main__":
    unittest.main()
