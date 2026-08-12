<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Architecture

Portscanner separates provider inventory, scheduling, network verification, and finding
policy. The separation is deliberate: a cloud API observation is not network evidence,
and scanner output is not automatically a security finding.

## Lifecycle

The system follows **DISCOVER → PRIORITIZE → VERIFY → ACT**.

### DISCOVER

A snapshot adapter enumerates every supported resource in its configured boundary and
emits a complete, generation-bearing set of Targets. The reconciler compares that set
with the last accepted complete snapshot:

- first discovery or reactivation after removal becomes a **new door**
  (`new_target`);
- an existing Target's public-address binding or scan-relevant non-policy lifecycle
  change becomes a **changed door** (`target_change`);
- an existing Target's attached security-group set or effective ingress change becomes
  a **changed door** (`policy_change`);
- unchanged entries remain **known doors** and receive scheduled `coverage`; and
- an absent entry is removed only after the adapter declares the snapshot complete.

Control-plane signals may request an early reread of one resource. They are hints, not
partial snapshots and not proof of a Target.

### PRIORITIZE

Policy converts inventory state into immutable work:

- new doors use fast full-TCP priority work;
- `target_change` uses fast full-TCP priority work with the same short freshness window
  as policy changes;
- `policy_change` uses priority work bounded by the current ingress-derived candidates,
  or fast full TCP when those candidates are not narrower;
- known doors stay on a periodic reconciliation cadence;
- every item has a deadline, maximum attempts, and scan profile; deployment-wide
  scanner rates, a hard active-Pod quota, and per-destination serialization bound
  execution;
- deterministic keys collapse duplicate snapshot pages, signals, and deliveries.

The scheduling rule is: **The sweep continues. The change jumps the line.**

Priority work may overtake scheduled work, but cannot consume the baseline queue
indefinitely.

### VERIFY

Before dispatch, the source adapter rereads the current provider object and returns an
ownership verdict for the exact Target identity, address, and generation:

- `ACTIVE`: the binding still belongs to the expected active Target generation;
- `STALE`: the generation or scan-relevant current state changed;
- `MOVED`: the address or resource binding moved;
- `INACTIVE`: the resource/binding is confirmed absent or inactive;
- `UNKNOWN`: the source could not return one trustworthy current owner.

Only `ACTIVE` can reach a scanner. All other verdicts suppress dispatch and trigger
reconciliation or bounded retry according to policy.

Workers run from an explicitly approved outside vantage. They receive only normalized
Targets and scan policy; they do not call provider inventory APIs.

### ACT

The evidence path stores an immutable result envelope and raw scanner evidence, then
normalizes observations:

- successful, complete evidence can establish a reachable or not-observed Exposure
  within its declared coverage;
- failed, timed-out, stale, missing, malformed, or incomplete evidence remains
  **UNKNOWN**;
- detection policy combines Exposure state with current context to create or update a
  Finding;
- later complete evidence may resolve a Finding, while missing evidence cannot.

## Logical components

1. **Source adapters** normalize complete inventory snapshots and optional signal
   payloads into provider-neutral contracts.
2. **Snapshot reconciler** atomically accepts complete snapshots, derives upserts and
   removals, and schedules periodic coverage.
3. **Priority scheduler** applies profiles, deadlines, fairness, leases, and retry
   policy.
4. **Ownership gate** calls the originating adapter immediately before dispatch.
5. **Orchestrator** converts accepted work into bounded Kubernetes Jobs.
6. **Scanner workers** perform policy-constrained outside-vantage verification and
   upload immutable evidence.
7. **Evidence parser** validates envelopes, records coverage and outcome, and updates
   Exposure state idempotently.
8. **Finding engine** applies operator-owned policy and emits lifecycle events.
9. **State stores** hold queues, leases, snapshots, evidence, normalized state, and
   audit history.

## Contract boundaries

Provider adapters depend on source contracts, not scanner or parser implementation.
Scanner workers consume only a normalized dispatch contract. Parsers consume only a
versioned result envelope and evidence format. This permits a new provider adapter
without importing scanner command construction, Kubernetes types, parser database
models, or finding rules.

Every cross-component record carries:

- a schema version;
- deterministic event and idempotency identifiers;
- Target identity and monotonic generation;
- source, observation, collection, dispatch, start, and completion timestamps as
  applicable;
- scan profile and declared coverage;
- trace correlation; and
- an explicit outcome, including UNKNOWN-causing failures.

`TargetEvent` keeps the reason distinction on the wire. `new_target` and
`target_change` use `target.upsert`; only `policy_change` uses `policy.changed` and
includes a `PolicyChange` object. `coverage` and `manual` use `rescan.requested`.
Generator-facing readable statuses map `new_target` to **New door**, both change
reasons to **Changed door**, `coverage` to **Known door**, and `manual` to
**Manual verification**.

## Core invariants

- A complete snapshot is replaced atomically; an interrupted page walk removes nothing.
- A signal causes a current-state reread; its payload is never accepted as current truth.
- Target identity does not change when mutable labels or display names change.
- Generation never decreases for one Target identity.
- Ownership is revalidated immediately before dispatch.
- One deterministic work key produces at most one effective dispatch.
- A result can only update the Target generation it names.
- Negative Exposure state requires complete declared coverage and successful evidence.
- UNKNOWN is preserved through storage, metrics, and APIs; it is not coerced to closed.
- Priority scheduling never eliminates periodic reconciliation.

## Default deployment boundary

The default deployment is one AWS account containing source, queue, orchestration,
evidence, and state resources. An optional hub/spoke design centralizes scheduling and
scanning while source accounts expose narrowly scoped read roles or forward normalized
events. See [multi-account deployment](multi-account.md).

The trust boundary and threats are detailed in [security-model.md](security-model.md).
