<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Adding inventory and signal sources

This guide defines the implementation contract for a new cloud, on-premises, or asset
inventory source. A source can provide:

- a **complete inventory snapshot**;
- an optional **change signal** that accelerates a current-state reread; or
- both.

Every production source needs a complete snapshot path. A signal-only integration is
not sufficient because events can be missed, duplicated, reordered, delayed, or
disabled.

## Architectural boundary

A provider adapter ends at normalized source contracts. It must not import or call:

- scanner command construction;
- Kubernetes Job or custom-resource types;
- result parser/database models;
- exposure reconciliation code; or
- finding/detection policy.

Conversely, scanners and parsers must not import provider SDKs or understand provider
resource payloads. The scanner consumes a normalized dispatch record. The parser
consumes a versioned result envelope and scanner evidence.

This boundary keeps a new provider adapter independent of scanner/parser internals. A
source change can add Targets without changing how packets are generated or evidence is
parsed.

## Required contracts

The current extension point is
`portscanner_inventory.base.SnapshotBackend`:

```python
class SnapshotBackend(Protocol):
    def collect(self) -> SnapshotBatch: ...
```

`collect()` owns the provider API page walk and returns one bounded decision:

```python
@dataclass(frozen=True)
class SnapshotBatch:
    scope: SnapshotScope
    targets: tuple[NormalizedTarget, ...]
    completion: ScopeCompletion  # COMPLETE, PARTIAL, or FAILED
    pages: int
    malformed_records: int
    failure_code: str | None
```

The signal and ownership side uses the concrete source primitives
`SignalHint`, `Resolution`, and `OwnershipCheck`. A provider implementation supplies
equivalents of:

```python
def parse_signal(envelope: Mapping[str, object]) -> SignalHint: ...
def resolve_hint(hint: SignalHint) -> Resolution: ...

class OwnershipValidator:
    def validate(self, target_id: str, generation: int) -> OwnershipCheck: ...
```

The first release wires these functions directly for AWS. A second provider should add
an explicit inventory-side provider registry/factory rather than adding provider
conditionals to scanner or parser code.

### SnapshotScope

`SnapshotScope` defines the exact state domain covered by one `SnapshotBatch`:

- source/backend type;
- account/project/tenant boundary supplied through protected configuration;
- Region/location or named aggregator;
- supported resource types; and
- metadata allowlist version, when it affects coverage.

The current type recognizes the AWS Config and direct EC2 scopes. A new provider must
extend scope validation and key serialization without changing existing keys. If a
provider cannot return one consistent global snapshot, divide it into stable named
partitions and reconcile removals independently in each partition.

### Pages and completion

Pagination tokens remain private to the backend. A page is never returned as a complete
snapshot. The backend follows every opaque cursor, detects loops/limits, normalizes and
deduplicates the collected records, and returns `ScopeCompletion.COMPLETE` only after
the provider confirms the final page with no malformed record. Any bounded failure
returns `PARTIAL` or `FAILED` plus a non-sensitive `failure_code`.

### Target

The adapter first produces a `NormalizedTarget` containing:

- stable internal `target_id`;
- provider scope and resource/address-binding locator;
- typed address, resource type, and location;
- lifecycle and scan-relevant policy fingerprint;
- bounded candidate ports derived from current provider state; and
- allowlisted metadata.

The state layer compares the normalized signature, allocates the monotonic generation
with a conditional write, and builds the versioned public `Target`/`TargetEvent`
contract. Do not let an adapter self-assign a generation or serialize directly to the
scanner queue.

Keep identity and change reason separate. For an existing stable Target identity, a
changed address binding or scan-relevant non-policy lifecycle field is
`target_change`, not `new_target`. A changed attached-policy set or effective ingress
fingerprint is `policy_change`. `new_target` is reserved for first discovery or
reactivation after a previously removed state.

The first release accepts public IPv4 Targets only. Reject private, reserved,
documentation, multicast, link-local, loopback, malformed, hostname, wildcard, and IPv6
Targets at normalization even if later safety gates would also reject them.

### SignalHint

A hint contains:

- signal schema version and source ID;
- provider event ID;
- provider event/observation time and collection time;
- one or more allowlisted resource locators;
- coarse change kind;
- optional bounded candidate-port hints; and
- trace correlation.

It does not contain authoritative address ownership, Target metadata, scan profile,
scanner arguments, or a deletion instruction. Candidate ports are hints only and must be
recomputed/bounded from the current provider reread.

### OwnershipCheck

The current contract returns an `OwnershipCheck` with:

- verdict: `ACTIVE`, `STALE`, `MOVED`, `INACTIVE`, or `UNKNOWN`;
- normalized current state when it is safe and useful; and
- a bounded non-sensitive reason code.

The validator receives Target ID and expected generation. Only `ACTIVE` authorizes
dispatch. A reason string is diagnostic and must not contain a
raw provider payload or sensitive identifier.

## Stable Target identity

Identity answers “is this the same logical address binding?” It must not depend on
display name, mutable tags, collection time, signal ID, page order, or serialization
order.

A typical canonical identity input is:

```text
provider
+ source boundary ID
+ location
+ provider resource type
+ provider resource identity
+ stable address-binding slot
```

Hash the length-delimited canonical form if an opaque public ID is needed. Do not
concatenate ambiguous free-form strings.

For a resource with several address bindings, use a provider-native allocation/binding
identifier. If the provider exposes no stable slot, include the normalized address in
the identity and model an address change as one removal plus one new Target.

Never use an account number or raw provider resource ID as the externally logged Target
ID.

## Monotonic generations

Generation answers “which accepted state of this Target is current?” For one
`target_id`, it must:

- be an integer;
- never decrease;
- remain the same for an idempotent reread of identical relevant state; and
- increase whenever address ownership or scan-relevant normalized state changes.

Use the existing persisted compare-and-swap counter keyed by Target ID and normalized
signature. A provider-native revision can contribute to the signature only when its
semantics are documented; it does not replace the state-layer generation fence.

Do not derive generation from wall-clock seconds, an unordered event timestamp, a random
number, or a hash. Signals can arrive out of order. Competing updates retry the
conditional read/write and either allocate exactly one next generation or observe the
winner.

The relevant fingerprint should include only normalized fields that affect ownership,
authorization, or scan policy. Metadata that is intentionally informational should not
create endless changed-door work.

## Complete snapshots and removals

Removal is the most dangerous snapshot operation. Follow this rule:

> A Target may be removed only because it is absent from a successfully completed
> snapshot of the same declared boundary and partition.

Implementation sequence:

1. Establish one stable `SnapshotScope`.
2. Walk every page using opaque cursors.
3. Validate and stage normalized Targets before returning a batch.
4. Detect cursor loops, duplicate pages, unexpected scope changes, and source
   freshness violations.
5. Return `COMPLETE` only after the provider confirms the final page with no malformed
   record; otherwise return `PARTIAL`/`FAILED`.
6. Reconcile upserts through conditional state-and-outbox transactions.
7. Consider absence/removal only when the batch is `COMPLETE`.
8. Revalidate each absent Target and conditionally fence its removal by the expected
   active generation.

Timeout, throttling, parse failure, process exit, permission denial, page-limit breach,
or provider inconsistency makes the batch non-complete and emits no removals. Retain a
bounded failure code and retry the entire affected partition.

An empty complete snapshot can be valid, but an unexpected large drop should enter
quarantine for operator review without being reclassified as success. Document the
source-specific anomaly threshold; it is an acceptance guard, not a substitute for
completeness.

Signals, point reads, and partial snapshots never remove Targets.

## Signals are hints

Signal handling is always:

```text
authenticate envelope
→ validate source and event shape
→ deduplicate event ID
→ extract resource locator
→ reread current provider state
→ normalize current state
→ compare/allocate generation
→ apply central priority policy
```

Do not trust an event's embedded address, tags, owner, security rule, deletion marker,
or timestamp as current state. If the current reread is missing, ambiguous, stale, or
unavailable, record that outcome and let snapshot reconciliation decide lifecycle.

Coalesce bursts by source and stable resource locator. Reordered older hints should
produce the same current reread result and no additional effective work.

## Ownership revalidation

The source must support a cheap, strongly scoped reread suitable immediately before
dispatch. Validate all of:

- same provider and source boundary;
- same provider resource identity;
- same address-binding identity and address;
- same expected generation/fingerprint;
- current resource class and location;
- current account/CIDR authorization; and
- source freshness within policy.

Do not cache an `ACTIVE` verdict beyond the configured dispatch window. A retry,
reschedule, or lease takeover repeats the reread.

Map failures explicitly:

- generation or scan-relevant policy changed → `STALE`;
- address/resource binding changed → `MOVED`;
- confirmed absence or inactive lifecycle → `INACTIVE`;
- multiple possible owners or inconsistent current state → `UNKNOWN`;
- timeout, throttling, permission failure, malformed response, or stale provider view →
  `UNKNOWN`.

Only a trustworthy positive match is `ACTIVE`.

## Metadata allowlist and redaction

Define the adapter allowlist next to the adapter version. For every field specify:

- normalized key and type;
- source path;
- maximum length/cardinality;
- whether it affects generation or policy;
- whether it may appear in logs/Findings; and
- redaction behavior.

Drop all unlisted fields before constructing a Target. In particular, do not retain full
provider payloads, arbitrary labels/tags, descriptions, user data, hostnames, personal
contact information, credentials, or unbounded network policy bodies. Provider account
and resource identifiers needed for identity/reread belong only in typed contract/state
fields; never duplicate them into free-form metadata or logs.

Use opaque references for owner and source. Logs use Target ID, trace ID, verdict, and
bounded reason codes. Tests must prove that an unexpected source field does not survive
normalization.

## Profile, priority, and deadline policy

The adapter reports normalized facts and a coarse change kind. Central policy—not the
adapter or signal—selects:

- `new_target` (**New door**) for first discovery or reactivation;
- `target_change` (**Changed door**) for address-binding or scan-relevant non-policy
  lifecycle changes;
- `policy_change` (**Changed door**) for attached-policy or effective-ingress changes;
- `coverage` (**Known door**) for periodic work on unchanged active Targets;
- `manual` (**Manual verification**) only for an explicit operator request;
- priority class;
- named scan profile;
- global/source/destination rate class;
- deadline;
- retry limit; and
- periodic reconciliation cadence.

The adapter must never emit scanner flags or executable command fragments.

Compute freshness from source observation and collection timestamps. If an item cannot
be verified before its deadline, expire it without dispatch and rely on current
snapshot state. Reserve scheduler capacity for known-door reconciliation:
**The sweep continues. The change jumps the line.**

## Registration and configuration

Adding code is not enough. The first release has direct AWS wiring, so a new provider
must make the inventory boundary explicitly extensible:

1. Put provider SDK interaction and normalization under
   `inventory/src/portscanner_inventory/<provider>/`.
2. Extend `SnapshotScope` source validation/key encoding without changing existing AWS
   keys, and register a `SnapshotBackend` factory in the inventory snapshot handler.
3. Register the signal parser and current-state resolver in the inventory signal
   handler. Do not route raw provider events outside `inventory/`.
4. Register a provider-specific ownership validator returning the shared
   `OwnershipCheck`.
5. Extend inventory `Settings` with deny-by-default source ID, boundaries, locations,
   cadence, signal enablement, metadata allowlist, and freshness limits.
6. Add/extend shared contract provider/resource enums only when needed, regenerate JSON
   Schemas/examples, and preserve the rolling compatibility window.
7. Map normalized change facts to the central `ScanReason`/`ScanProfile` policy:
   first discovery/reactivation to `new_target`, address or non-policy lifecycle
   changes to `target_change`, attached-policy/ingress changes to `policy_change`, and
   periodic unchanged work to `coverage`. `target_change` must request fast full TCP,
   use `target.upsert`, and omit `PolicyChange`. Default unknown facts to no dispatch.
8. Add metrics with bounded labels; never label by address or raw resource ID.
9. Add dead-letter/quarantine routing and operator runbook entries.
10. Document provider consistency, pagination, revision, deletion, throttling, and
    current-state-read semantics.

Unknown adapter types, schema versions, resource types, or change kinds fail closed.

No registration step belongs in `scanner/`, `parser/`, the Kubernetes operator, or the
finding engine. Those components continue to consume the existing provider-neutral
TargetEvent/ScanResult boundaries.

## IAM and Terraform wiring

Create a dedicated least-privilege source identity. Separate permissions for:

- complete inventory list/query;
- one-resource current-state get;
- optional event receive/forward;
- queue/object publication; and
- metrics/log writes.

Do not give the adapter packet-sending, Kubernetes Job creation, evidence parsing,
database migration, or finding-publication permissions. Scanner workers receive no
provider inventory role.

Terraform changes should include:

1. variables with no live defaults for source boundary and role references;
2. source module/resources behind `enabled = false` by default;
3. existing-service reference mode before create mode for account-wide inventory or
   audit services;
4. least-privilege policy tests;
5. encrypted queues and dead-letter queues;
6. filtered event rules only when signals are enabled;
7. OIDC/workload identity rather than static keys;
8. outputs that avoid account numbers and role/resource IDs where possible; and
9. staged activation documented in [aws-deployment.md](aws-deployment.md).

For hub/spoke, add spoke trust and event-bus policy independently. A forwarded event
still requires a hub-readable current-state path. Never commit a live account,
organization, role, resource, state, variable file, key, or kubeconfig.

## Fixtures and tests

### Fixtures

Create minimal synthetic fixtures for:

- one complete page and a multi-page snapshot;
- duplicate resources/pages;
- no public address;
- multiple address bindings;
- changed relevant state;
- unrelated metadata;
- create/update/delete-like signals;
- stale and reordered events;
- active, stale, moved, inactive, and unavailable/ambiguous rereads; and
- malformed/oversized provider payloads.

Use only RFC 5737/3849 addresses and synthetic identifiers. Keep payloads minimal; do
not copy provider-console exports or production events.

### Contract tests

Prove that serialized Targets and hints:

- validate against the current schema;
- have deterministic canonical serialization and IDs;
- preserve timestamp meaning and ordering;
- reject unknown versions and fields where required;
- contain only allowed metadata; and
- remain readable across the documented rolling-upgrade window.

### Unit tests

Prove:

- every pagination cursor is followed once and cursor loops fail;
- duplicate and reordered input is idempotent;
- identity is stable under name/tag/order changes;
- relevant change increments generation exactly once;
- public-address and non-policy lifecycle changes emit `target_change`, never
  `new_target`;
- attached-policy or effective-ingress changes emit `policy_change`;
- first discovery and reactivation after removal emit `new_target`;
- generation never decreases;
- incomplete snapshots remove nothing;
- only complete-snapshot absence emits removal;
- signals force a current-state reread;
- no signal field becomes authoritative Target state;
- each ownership failure maps to the correct non-`ACTIVE` verdict;
- account/CIDR/resource gates fail closed;
- metadata allowlist and bounds hold;
- throttling/backoff respects deadlines; and
- exceptions do not leak sensitive payloads.

### Integration tests

With a fake provider and local queues/state:

1. commit a complete snapshot;
2. replay it and observe no duplicate effective work;
3. change one resource and observe one changed-door item;
4. deliver duplicate/reordered hints and observe one reread/current generation;
5. advance ownership between scheduling and dispatch and observe suppression;
6. abort a later snapshot and observe no removals;
7. complete the snapshot and observe deterministic removal;
8. replay work/results and observe idempotent state;
9. simulate provider/database/queue outages and preserve UNKNOWN; and
10. verify the known-door sweep progresses under a hint burst.

A live provider test is manual, read-only until separately authorized, uses protected
environment variables, and always cleans up project-created resources. Public CI never
scans a live destination.

## Failure and UNKNOWN expectations

Classify failures so operators can distinguish source health from network evidence:

- source timeout/throttling/permission/schema failure: source UNKNOWN, no removal;
- signal parse/auth failure: quarantine, no reread or dispatch;
- ownership UNKNOWN: no dispatch;
- expired work: no dispatch;
- scanner failure/timeout/partial coverage: Exposure UNKNOWN;
- evidence upload or parse failure: durable retry/quarantine, Exposure unchanged;
- unsupported result/schema version: quarantine, no state mutation; and
- finding publication failure: retry from durable normalized state.

Never convert absence of a provider response, event, result object, XML/JSON field,
scanner process, or parser record into a closed Exposure.

## Idempotency expectations

Use deterministic keys at every boundary:

```text
snapshot state = source + scope + target + normalized signature
signal hint  = source + provider event ID
work         = target ID + generation + profile + policy version
dispatch     = work ID + ownership-check version
result       = dispatch ID + attempt
state update = target ID + generation + declared coverage
```

Hash canonical, length-delimited values. Idempotency records must be conditional writes,
not check-then-write races. A retry can refresh a lease or return the previous result,
but cannot create a second effective dispatch or regress state.

## End-to-end pseudocode

```python
def reconcile_source(backend, state, ownership, source):
    batch = backend.collect()
    for target in batch.targets:
        state.reconcile(target, source=source)  # conditional state + outbox

    if batch.completion != ScopeCompletion.COMPLETE:
        return  # partial/failed collections remove nothing

    observed = {target.target_id for target in batch.targets}
    for prior in state.active_in_scope(batch.scope):
        if prior.target_id in observed:
            continue
        check = ownership.validate(prior.target_id, prior.generation)
        if check.verdict == OwnershipVerdict.INACTIVE:
            state.remove(prior, source=source)  # generation-fenced


def handle_signal(parse_signal, resolver, state, envelope):
    hint = parse_signal(envelope)
    if not state.claim_signal(hint.event_id):
        return
    resolution = resolver.resolve(hint)  # provider current-state reads
    if resolution.status == ResolutionStatus.UNKNOWN:
        raise RetryableSourceError
    for target in resolution.targets:
        state.reconcile(target, reason="signal_hint")


def dispatch(ownership, work, policy):
    require_unexpired(work)
    require_policy_scope(work.target, policy)
    check = ownership.validate(work.target_id, work.target_generation)
    if check.verdict != OwnershipVerdict.ACTIVE:
        record_suppressed(work, check)
        return
    require_policy_scope(check.current, policy)  # check again after reread
    create_normalized_scan_job(work, policy.named_profile(work.profile))
```

The final function receives no provider payload and emits no provider-specific scanner
arguments.

## Review checklist

Source contract:

- [ ] Source boundary and partition semantics are explicit.
- [ ] Snapshot completeness and consistency are documented.
- [ ] Stable Target identity excludes mutable fields.
- [ ] Generation is monotonic, persisted, and duplicate-safe.
- [ ] Multi-address resources have a stable binding rule.
- [ ] Removal occurs only after a complete snapshot.
- [ ] Signals are hints followed by current-state rereads.
- [ ] Dispatch-time ownership supports every non-`ACTIVE` verdict.

Safety and data:

- [ ] Supported resource/address types are allowlisted.
- [ ] Account and CIDR gates default empty.
- [ ] Provider policy and authorization are documented.
- [ ] Metadata is allowlisted, bounded, and redacted.
- [ ] No raw payload reaches logs, scanner, parser, or Findings.
- [ ] Profiles are named and centrally selected.
- [ ] Priority, fairness, deadlines, rates, and retries are bounded.
- [ ] UNKNOWN is preserved for every incomplete path.

Implementation:

- [ ] Adapter is registered without scanner/parser imports.
- [ ] Configuration schema and feature gates default disabled.
- [ ] IAM separates list, reread, event, and publication permissions.
- [ ] Terraform supports existing-service mode and staged activation.
- [ ] Hub/spoke trust is scoped and signals retain a reread path.
- [ ] Metrics have bounded, non-sensitive labels.
- [ ] Dead-letter, quarantine, rollback, and cleanup are documented.

Verification:

- [ ] Synthetic fixtures use only RFC 5737/3849 addresses and invented IDs.
- [ ] Contract, unit, integration, failure, and idempotency tests pass.
- [ ] Incomplete snapshots are proven not to remove Targets.
- [ ] Duplicate/reordered signals are proven harmless.
- [ ] Ownership changes between queue and dispatch suppress the scan.
- [ ] Known-door reconciliation progresses under priority load.
- [ ] Sanitizer, secret scan, IaC, manifest, image, and generated-drift checks pass.
- [ ] A separately authorized low-rate canary and cleanup plan are reviewed.
