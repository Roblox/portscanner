<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Multi-account deployment

Single-account operation is the default. Multi-account operation is optional and should
be adopted only when centralized ownership, authorization, incident response, and
network egress are already defined.

## Patterns

### Independent accounts

Each account runs its own inventory, scheduling, scanner, evidence, and state. This has
the smallest cross-account trust boundary and clearest cost attribution, but duplicates
infrastructure and policy.

### Hub with assumed read roles

The hub runs inventory, scheduling, scanning, evidence, and state. Each spoke exposes a
read role for:

- supported inventory list/get operations;
- the specific current-state get required for ownership revalidation; and
- optional read-only access to an existing inventory aggregator.

The role does not grant network mutation, security-group changes, pass-role,
credential creation, or scan dispatch. The hub stores a role reference in protected
deployment configuration, not in the public repository.

### Hub with event forwarding

Spokes filter supported provider events and forward them to a hub event bus or queue.
The hub authenticates the source and extracts a bounded `SignalHint`/resource locator.
This can reduce signal delay, but it does not replace:

- complete periodic snapshots;
- a current provider-state reread;
- dispatch-time ownership revalidation; or
- account and CIDR authorization gates.

A forwarded event is a hint. Its mutable fields never become authoritative Target
metadata or scanner arguments.

The AWS member module forwards only its provider Region. Its EC2 API-call pattern emits
nothing without a member or organization management CloudTrail, so active forwarding
requires `cloudtrail_mode = "create"` or an explicit `existing_cloudtrail_arn`. A
multi-Region trail supplies CloudTrail history, but EventBridge default buses and rules
are regional. Deploy a uniquely named member forwarding root in every Region requiring
the hot path, all targeting the central regional bus; use snapshots elsewhere.

### Hybrid

Spokes forward signals while the hub assumes a read role for snapshots and rereads.
This is the preferred centralized pattern when change acceleration is required.

## Trust design

For each spoke:

- trust only the dedicated hub source identity;
- constrain OIDC subject, principal, external condition, partition, and Region where
  supported;
- grant only named inventory list/get actions;
- restrict resources when the provider API supports effective resource scoping;
- require short sessions and log every assume-role operation;
- prevent role chaining into unrelated identities; and
- keep scanner workers unable to assume spoke roles.

Separate the source-reader identity from the Terraform deployment identity. Event-bus
resource policy should accept only approved spokes and only the expected event shape.
Use a per-spoke source identifier that is not a live account number in logs and metrics.

## Account registry

Maintain the live registry in protected operator configuration. Each entry should
contain:

- opaque source ID;
- account reference supplied at deployment time;
- enabled Regions and resource classes;
- snapshot adapter and optional signal route;
- read-role reference;
- authorized CIDRs and exclusions;
- profile and rate ceilings;
- authorization/change-record reference;
- metadata allowlist version; and
- enabled, paused, or decommissioning state.

Repository examples use `${SPOKE_ACCOUNT_ID}` and `${SPOKE_READ_ROLE}` placeholders.
Never commit account numbers, role ARNs, organization IDs, or external-condition values.
The Terraform examples expose these values as variables with synthetic defaults. Put
live account maps, names, Regions, ARNs, and external IDs only in ignored private
variable files.

## Source isolation

- Namespace snapshot cursors, deterministic IDs, queues, leases, and object prefixes by
  opaque source ID.
- Include source ID in every Target and result correlation key.
- Prevent one source's snapshot from removing another source's Targets.
- Before mutually untrusted or large-scale multi-source rollout, add per-source API,
  queue, dispatch, and packet budgets; the first release provides a deployment-wide Pod
  quota and destination serialization, not an independent per-source packet bucket.
- Quarantine malformed or unauthorized spoke events without blocking other sources.
- Ensure database authorization and queries cannot cross source boundaries accidentally.

Stable Target identity should include provider, source boundary, Region or location,
provider resource identity, and address binding as defined by the adapter contract.
Display names and mutable tags are not identity.

## Onboarding a spoke

1. Record explicit scanning authorization, provider-policy review, accounts, Regions,
   CIDRs, profiles, rates, and owner.
2. Choose snapshot-only, assume-role, event-forwarding, or hybrid mode.
3. Review existing Config and CloudTrail resources. For Config aggregation, create the
   source authorization in each exact member Region for the central account and
   aggregator Region before adding that source to an aggregator configured for that
   Region. The application create mode includes only its own provider Region; use direct
   snapshots or an externally provisioned existing aggregator for others. For event
   forwarding, choose member `cloudtrail_mode = "create"` or reference and live-verify
   a member/organization multi-Region management trail.
4. Deploy the spoke read role and one optional filtered event target per signal Region,
   with unique state/name and no dispatch grant.
5. Add the protected hub registry entry with dispatch disabled.
6. Run a complete snapshot and validate pagination, completeness, metadata redaction,
   identity, and generation.
7. Exercise `ACTIVE`, `STALE`, `MOVED`, `INACTIVE`, and `UNKNOWN` ownership paths.
8. Enable one narrow authorized canary at the lowest rate.
9. Confirm evidence isolation, idempotent replay, cost attribution, and cleanup.
10. Enable periodic reconciliation, then optional signals.

## Failure behavior

- A spoke API failure pauses only that source and yields UNKNOWN ownership.
- An incomplete snapshot cannot remove Targets.
- An event-forwarding outage does not stop periodic snapshots.
- Hub queue pressure preserves reserved baseline capacity and per-source fairness.
- Expired work is discarded before role assumption or Job creation.
- If a spoke is removed from authorization, dispatch stops before queued work is
  reconciled.

No cross-source fallback is allowed: the hub must not scan a Target under another
spoke's authorization because an API or role is unavailable.

## Offboarding

1. Disable dispatch and signals for the source.
2. Expire or remove queued work and verify no active Job remains.
3. Take a final complete snapshot if policy requires it, then mark Targets inactive.
4. Remove event-bus permissions and the spoke read-role trust.
5. Remove protected registry entries and source-specific secrets.
6. Apply evidence retention/deletion policy to queues, objects, state, logs, and backups.
7. Confirm shared Config, CloudTrail, VPC, and account services are unchanged.
8. Revoke the authorization record and review residual cost.
