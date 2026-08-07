<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Security model

Portscanner can emit network traffic, read cloud inventory, and retain security
evidence. Compromise can therefore cause unauthorized scanning, data disclosure, or
incorrect Findings. Deploy it with a smaller trust boundary than the assets it observes.

## Protected assets

- scanning authorization and account/CIDR policy;
- provider read roles and OIDC trust;
- Target ownership and generation state;
- queues, leases, and idempotency records;
- scanner profiles and rate limits;
- raw evidence, normalized Exposures, and Findings;
- database credentials and encryption keys;
- container images, manifests, migrations, and Terraform state; and
- audit records that correlate source, dispatch, evidence, and action.

## Trust boundaries

1. **Provider boundary:** source adapters read provider APIs. Provider payloads are
   untrusted input even when authenticated.
2. **Signal boundary:** events can be delayed, duplicated, reordered, forged through a
   compromised producer, or incomplete.
3. **Scheduling boundary:** normalized work crosses from cloud data into a system
   capable of network access.
4. **Kubernetes boundary:** the controller creates Jobs; scanner pods hold network-egress
   authority and evidence-write credentials.
5. **Evidence boundary:** result objects and scanner output are untrusted parser input.
6. **Finding boundary:** normalized state can trigger notifications or downstream
   operator action.
7. **CI/deployment boundary:** workflows can publish images and change infrastructure
   when explicitly trusted.

## Security invariants

- Account, CIDR, resource-type, profile, and rate gates are deny-by-default.
- Only assets with explicit authorization may be scanned.
- Provider policy terms and acceptable-use constraints override project configuration.
- Current ownership is revalidated immediately before every dispatch.
- Scanner workers cannot choose or expand Target scope.
- Source metadata cannot become command-line fragments.
- A signal cannot establish ownership, delete a Target, or assert an Exposure.
- Failed or incomplete work produces UNKNOWN, never a closed result.
- Evidence and state writes are idempotent and generation-scoped.
- Deployment credentials are short-lived; no static cloud key is committed or stored in
  an image.

## Threats and controls

### Recycled address or stale queue item

An address may move to another resource or customer after discovery. Stable Target
identity, monotonic generations, short work deadlines, and a current-state ownership
reread suppress stale dispatch.

### Forged or misleading signal

A signal is treated as a hint. The adapter uses only its locator and source identity to
request current provider state. Snapshot reconciliation repairs missed signals.

### Command or argument injection

Targets and metadata are parsed into typed values. The scheduler selects a named,
reviewed profile. The worker invokes the scanner without a shell and without accepting
free-form provider or user arguments.

### Scope expansion

The effective destination set is the intersection of current provider ownership,
account allowlist, CIDR allowlist, supported resource classes, and profile limits.
Normalization rejects hostnames, ranges, wildcards, or address families not enabled by
the release.

### Excessive traffic

Global, source, destination, and per-Job budgets limit packet rate and concurrency.
Deadlines, timeouts, maximum Target counts, disruption windows, and an emergency
dispatch-off switch bound impact.

### Malicious scanner output

Parsers impose file, XML/JSON depth, field length, count, and decompression limits; do
not resolve external entities; validate schema versions; and quarantine malformed
evidence. Database writes use parameters and least-privilege identities.

### Queue replay or duplicate delivery

Deterministic event, work, dispatch, and result keys make processing idempotent. Leases
have bounded duration and owner tokens. A result cannot update another Target
generation.

### Metadata or evidence disclosure

Adapters emit only allowlisted metadata. Logs redact addresses, account identifiers,
provider resource IDs, tags, and raw evidence. Storage uses encryption, narrow roles,
private network paths where appropriate, retention, and access logging.

### Compromised scanner pod

Scanner pods use a dedicated service account with no provider inventory access,
read-only root filesystem where supported, all Linux capabilities dropped, resource
limits, egress policy, and write-only
evidence access scoped to an immutable prefix. Never mount deployment credentials or a
kubeconfig.

### Supply-chain compromise

CI runs tests, generated-drift checks, static analysis, secret and publication
sanitizers, IaC validation, image scans, and license checks. Releases use immutable
digests and protected environments. Third-party actions and dependencies should be
pinned and updated through reviewed automation.

## IAM separation

Use distinct identities for:

- snapshot listing;
- one-resource ownership rereads;
- signal publication;
- queue consumption and lease updates;
- Kubernetes Job creation;
- evidence upload;
- parsing and state updates;
- Finding publication;
- migrations; and
- Terraform deployment.

Do not combine scanner network-egress authority with provider inventory reads. In hub/spoke
mode, each spoke role restricts trusted principal, external conditions where supported,
actions, Regions, and resources. Event forwarding does not grant dispatch authority.

## Residual risks

Outside-vantage scanning can still trigger provider or destination defenses, incur
egress cost, and affect fragile services. Provider inventory can be eventually
consistent. Port reachability does not establish vulnerability, and non-observation
within one profile does not establish safety. Operators remain responsible for
authorization, policy, monitoring, and incident response.
