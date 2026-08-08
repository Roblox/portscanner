# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

"""Regenerate synthetic contract examples with deterministic identifiers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from portscanner_contracts import (
    AddressFamily,
    AwsContext,
    AwsTags,
    CloudProvider,
    Finding,
    PolicyChange,
    ScanDirective,
    ScannerEngine,
    ScanOutcome,
    ScanProfile,
    ScanReason,
    ScanResult,
    ScanResultEnvelope,
    SourceObservation,
    Target,
    TargetEvent,
    TargetEventType,
    TargetRemoval,
    TcpPortRange,
    TransportProtocol,
    deterministic_sha256,
)


def build_examples() -> tuple[TargetEvent, TargetRemoval, ScanResultEnvelope, Finding]:
    """Build self-consistent synthetic work, removal, result, and finding documents."""

    event_time = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    observed_at = datetime(2026, 1, 15, 10, 0, 5, tzinfo=UTC)
    collected_at = datetime(2026, 1, 15, 10, 0, 12, tzinfo=UTC)
    requested_at = datetime(2026, 1, 15, 10, 1, tzinfo=UTC)
    deadline_at = datetime(2026, 1, 15, 10, 15, tzinfo=UTC)
    not_after = datetime(2026, 1, 15, 10, 30, tzinfo=UTC)
    started_at = datetime(2026, 1, 15, 10, 2, tzinfo=UTC)
    completed_at = datetime(2026, 1, 15, 10, 2, 18, tzinfo=UTC)

    candidate_ranges = (
        TcpPortRange(start=22, end=22),
        TcpPortRange(start=443, end=443),
        TcpPortRange(start=8443, end=8443),
    )
    previous_fingerprint = deterministic_sha256(
        "example.aws-policy.v1",
        {"revision": "previous"},
    )
    current_fingerprint = deterministic_sha256(
        "example.aws-policy.v1",
        {"revision": "current"},
    )

    target = Target.create(
        provider=CloudProvider.AWS,
        scope_id="123456789012",
        location="us-west-2",
        resource_id="eni-0123456789abcdef0",
        private_address="10.24.8.17",
        public_address="192.0.2.44",
        address_family=AddressFamily.IPV4,
        transport=TransportProtocol.TCP,
        generation=3,
    )
    source = SourceObservation.create(
        source_event_name="AwsConfigSnapshot",
        source_event_id="synthetic-event-0001",
        source_request_id="synthetic-request-0001",
        event_time=event_time,
        observed_at=observed_at,
        collected_at=collected_at,
    )
    policy_change = PolicyChange.create(
        target_id=target.target_id,
        previous_fingerprint=previous_fingerprint,
        current_fingerprint=current_fingerprint,
        changed_at=event_time,
        candidate_tcp_port_ranges=candidate_ranges,
    )
    directive = ScanDirective.create(
        target_id=target.target_id,
        target_generation=target.generation,
        reason=ScanReason.POLICY_CHANGE,
        profile=ScanProfile.TARGETED_TCP,
        priority=900,
        requested_at=requested_at,
        deadline_at=deadline_at,
        not_after=not_after,
        tcp_port_ranges=candidate_ranges,
    )
    aws_context = AwsContext(
        account_id="123456789012",
        region="us-west-2",
        network_interface_id="eni-0123456789abcdef0",
        private_ip="10.24.8.17",
        public_ip="192.0.2.44",
        instance_id="i-0123456789abcdef0",
        security_group_ids=(
            "sg-0123456789abcdef0",
            "sg-0fedcba9876543210",
        ),
        policy_fingerprint=current_fingerprint,
        candidate_tcp_port_ranges=candidate_ranges,
        source_event_name="AwsConfigSnapshot",
        source_event_id="synthetic-event-0001",
        source_request_id="synthetic-request-0001",
        tags=AwsTags(
            application="example-web",
            environment="test",
            name="synthetic-target",
            service="example-api",
        ),
    )
    event = TargetEvent.create(
        schema_version="1.0",
        event_type=TargetEventType.POLICY_CHANGED,
        target=target,
        source=source,
        policy_change=policy_change,
        scan=directive,
        aws_context=aws_context,
    )
    removal_time = datetime(2026, 1, 15, 11, 0, tzinfo=UTC)
    removal_target = Target.create(
        provider=target.provider,
        scope_id=target.scope_id,
        location=target.location,
        resource_id=target.resource_id,
        private_address=target.private_address,
        public_address=target.public_address,
        address_family=target.address_family,
        transport=target.transport,
        generation=target.generation + 1,
    )
    removal_source = SourceObservation.create(
        source_event_name="AwsConfigSnapshot",
        source_event_id="synthetic-event-removal-0001",
        source_request_id="synthetic-request-removal-0001",
        event_time=removal_time,
        observed_at=removal_time,
        collected_at=removal_time,
    )
    removal_context = AwsContext(
        account_id=aws_context.account_id,
        region=aws_context.region,
        network_interface_id=aws_context.network_interface_id,
        private_ip=aws_context.private_ip,
        public_ip=aws_context.public_ip,
        instance_id=aws_context.instance_id,
        security_group_ids=aws_context.security_group_ids,
        policy_fingerprint=aws_context.policy_fingerprint,
        candidate_tcp_port_ranges=aws_context.candidate_tcp_port_ranges,
        source_event_name=removal_source.source_event_name,
        source_event_id=removal_source.source_event_id,
        source_request_id=removal_source.source_request_id,
        tags=aws_context.tags,
    )
    removal = TargetRemoval.create(
        schema_version="1.0",
        event_type=TargetEventType.TARGET_REMOVED,
        target=removal_target,
        source=removal_source,
        aws_context=removal_context,
        removed_at=removal_time,
    )

    result = ScanResult.create(
        schema_version="1.0",
        event_id=event.event_id,
        directive_id=directive.directive_id,
        target=target,
        profile=directive.profile,
        scanner=ScannerEngine.NMAP,
        scanner_version=f"sha256:{'c' * 64}",
        started_at=started_at,
        completed_at=completed_at,
        outcome=ScanOutcome.COMPLETE,
        requested_tcp_port_ranges=candidate_ranges,
        scanned_tcp_port_ranges=candidate_ranges,
        open_tcp_ports=(443, 8443),
        exit_code=0,
        raw_result_sha256=deterministic_sha256(
            "example.raw-result.v1",
            {"event_id": event.event_id},
        ),
        error_code=None,
        error_message=None,
    )
    envelope = ScanResultEnvelope.model_validate(
        {
            "schema_version": "1.0",
            "event_id": event.event_id,
            "directive_id": directive.directive_id,
            "trace_id": event.event_id,
            "run_id": "example-run-0001",
            "attempt_id": "example-attempt-0001",
            "target": {
                "target_id": target.target_id,
                "address": target.public_address,
                "generation": target.generation,
            },
            "profile": directive.profile,
            "image_version": result.scanner_version,
            "coverage": {
                "protocol": "tcp",
                "ports": ["22", "443", "8443"],
                "complete": True,
            },
            "timestamps": {
                "scan_started_at": started_at,
                "scan_completed_at": completed_at,
                "result_uploaded_at": datetime(2026, 1, 15, 10, 2, 19, tzinfo=UTC),
            },
            "commands": {
                "discovery": {
                    "argv": [
                        "nmap",
                        "-p",
                        "22,443,8443",
                        "-oX",
                        "<raw-xml>",
                        "<authorized-target>",
                    ],
                    "timeout_seconds": 300,
                    "exit_code": 0,
                },
                "enrichment": {
                    "argv": [
                        "nmap",
                        "-sV",
                        "-p",
                        "443,8443",
                        "-oX",
                        "<raw-xml>",
                        "<authorized-target>",
                    ],
                    "timeout_seconds": 300,
                    "exit_code": 0,
                },
            },
            "outcome": "complete",
            "exit_code": 0,
            "raw_result": {
                "format": "nmap-xml",
                "bucket": "synthetic-results",
                "key": "verify/results/example/raw/nmap-discovery.xml",
                "sha256": result.raw_result_sha256,
                "enrichment": {
                    "bucket": "synthetic-results",
                    "key": "verify/results/example/raw/nmap-enrichment.xml",
                    "sha256": deterministic_sha256(
                        "example.raw-enrichment.v1",
                        {"event_id": event.event_id},
                    ),
                },
            },
            "error": None,
            "scan_result": result,
        }
    )
    fingerprint = deterministic_sha256(
        "act-finding-v1",
        {
            "rule_key": "public-tls-service",
            "target_id": target.target_id,
            "protocol": "tcp",
            "port": 443,
        },
    )
    finding = Finding.model_validate(
        {
            "schema_version": "1.0",
            "kind": "finding_event",
            "finding": {
                "fingerprint": fingerprint,
                "target_id": target.target_id,
                "provider": target.provider,
                "generation": target.generation,
                "protocol": target.transport,
                "port": 443,
                "rule_key": "public-tls-service",
                "status": "open",
                "severity": "high",
                "title": "Public TLS service",
                "description": "A synthetic public TLS service is reachable.",
                "observed_address": target.public_address,
                "service": {
                    "name": "https",
                    "product": "synthetic-service",
                    "version": "1.0",
                    "certificate_sha256": "e" * 64,
                    "ssh_host_key_sha256": None,
                    "banner_sha256": None,
                    "identity_sha256": deterministic_sha256(
                        "example.service-identity.v1",
                        {"name": "https", "product": "synthetic-service", "version": "1.0"},
                    ),
                },
                "first_opened_at": completed_at,
                "last_seen_at": completed_at,
                "last_changed_at": completed_at,
                "resolved_at": None,
                "resolution_reason": None,
                "version": 1,
            },
            "event": {
                "event_key": deterministic_sha256(
                    "act-finding-event-v1",
                    {"fingerprint": fingerprint, "version": 1},
                ),
                "event_type": "opened",
                "previous_status": None,
                "new_status": "open",
                "reason": "exposure_open",
                "occurred_at": completed_at,
                "source": {
                    "kind": "scan_attempt",
                    "key": envelope.attempt_id,
                },
            },
        }
    )
    return event, removal, envelope, finding


def main() -> None:
    """Write all checked-in example documents."""

    output_directory = Path(__file__).resolve().parent
    documents = dict(
        zip(
            (
                "target-event.json",
                "target-removal.json",
                "scan-result.json",
                "finding.json",
            ),
            build_examples(),
            strict=True,
        )
    )
    for filename, document in documents.items():
        (output_directory / filename).write_text(
            f"{document.to_json(indent=2)}\n",
            encoding="utf-8",
        )
        print(filename)


if __name__ == "__main__":
    main()
