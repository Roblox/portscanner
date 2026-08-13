<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Portscanner inventory

Inventory establishes which public address the deployment is authorized to
scan. It is the source of target identity, monotonic generation, current
ownership, and bounded scan policy; scanner output never creates inventory.

## AWS model

The first release supports public IPv4 addresses attached to supported AWS
EC2 network interfaces. A target identity is stable across observations while
its address, security-group policy, lifecycle state, and generation may
change.

Authoritative snapshots use either direct EC2 reads or an explicitly
configured AWS Config aggregator. Optional EventBridge and CloudTrail signals
are acceleration hints: they trigger a current-state reread but are not trusted
as inventory evidence by themselves.

Snapshot reconciliation writes target state and a transactional outbox record
in one DynamoDB transaction. The outbox publishes an immutable `TargetEvent`
to S3 and the appropriate queues. DynamoDB Streams is the fast path; a bounded
repair schedule retries pending outbox rows.

## Dispatch safety

Before a scan is created, inventory and generator checks enforce:

- an explicitly authorized account and Region;
- deny-before-allow IPv4 CIDR policy;
- a supported resource class and optional target-selection tags;
- an active target at the expected generation; and
- an immediate provider reread of the address binding and scan-relevant
  security-group state.

`STALE`, `MOVED`, `INACTIVE`, ambiguous, incomplete, or out-of-scope state
must not dispatch. Provider addresses can be recycled, so a queued event alone
never proves present ownership.

Complete snapshots may reconcile absence. Scoped canary reads and partial or
failed snapshots must not remove targets they did not observe.

## Default evaluation

The canonical AWS deployment creates one isolated managed canary and invokes a
single scoped snapshot. Only that target receives the evaluation's
`targeted-tcp` directive. Periodic account inventory and signal processing
remain disabled until the operator edits the same environment file and
explicitly activates an authorized account, CIDR, and tag scope.

## Adding an inventory source

New providers are not enabled by adding arbitrary scanner targets. A source
adapter must provide:

1. Stable provider target identity and monotonic generation semantics.
2. Complete-snapshot boundaries and explicit partial/failure behavior.
3. Current ownership revalidation immediately before dispatch.
4. Normalized lifecycle, address, location, and minimized context.
5. Provider-policy, account/project, CIDR, pagination, and rate bounds.
6. Deterministic synthetic fixtures for create, change, removal, stale work,
   pagination, retries, and recycled-address suppression.

Signals must resolve to a provider reread and cannot emit removals from an
unverified event payload. Keep provider SDK objects and credentials outside
the public contracts and finding exports.

Run the focused package checks from the repository root:

```sh
uv run --package portscanner-inventory pytest inventory/tests
```

Contract, Terraform, generator, and end-to-end boundary tests are also
required for any source that can cause network traffic.
