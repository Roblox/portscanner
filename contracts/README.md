<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Portscanner contracts

This package owns the provider-neutral records exchanged between inventory,
dispatch, scanning, ingestion, and optional finding consumers. Runtime
components must parse these models instead of maintaining looser local copies.

## Contracts

- `TargetEvent` declares one authoritative target generation and, when
  applicable, one bounded scan directive.
- `ScanResultEnvelope` references immutable raw evidence and contains one
  normalized `ScanResult`.
- `Finding` is a policy result derived from accepted exposure state. It is not
  raw Nmap output.

Canonical Python models live in `src/portscanner_contracts`. Generated JSON
Schemas live in the repository `schemas/` directory, and synthetic examples
live in `examples/`. Examples contain documentation-only identifiers and are
contract fixtures, not runnable scan requests.

Identifiers are deterministic. Timestamps are UTC, object shapes are closed,
and unknown fields are rejected. A failed or incomplete scan remains
`UNKNOWN`; consumers must not infer that an unobserved port is closed.

## Compatibility

The 1.x contracts follow Semantic Versioning. A contract change must update
the model, generated Schema, examples, producers, consumers, and compatibility
tests together. Never reuse a schema version for an incompatible shape.

Regenerate and test from the repository root:

```sh
make generate
make test-contracts
```

Generated files are committed so deployments and non-Python consumers can pin
the exact release contract.

## Consuming finding exports

PostgreSQL findings are the default system boundary. S3/SQS export is an
optional integration enabled in the AWS environment configuration.

When export is enabled, SQS messages are S3 object notifications, not Finding
payloads. A consumer must:

1. Verify the configured bucket, prefix, object version, and size before
   download.
2. Fetch that exact object version and verify its declared payload SHA-256.
3. Validate the JSON Schema and semantic model.
4. Commit downstream state idempotently using the finding event key and
   finding version.
5. Delete the SQS message only after the downstream commit succeeds.

S3 notifications and SQS delivery are at least once and may be delayed or
reordered. Consumers must tolerate duplicates, reject malformed pointers, and
send repeatedly failing messages to their own reviewed quarantine path.

Finding documents intentionally omit raw XML, credentials, private cloud
metadata, and scanner command output. Integrations should preserve that
minimized boundary rather than joining directly to internal tables.

## Security review

Changes to identity, generation, freshness, coverage, evidence eligibility,
hashing, or finding resolution semantics are security-sensitive. Use only
synthetic fixtures and run the full repository checks before review.
