<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Portscanner

Portscanner is a self-hosted reference architecture for continuously verifying the
Internet-facing ports of cloud assets you are authorized to test. It combines complete
inventory snapshots, optional change signals, bounded scan policy, and outside-vantage
evidence.

Its operating loop uses the exact lifecycle:

> **DISCOVER → PRIORITIZE → VERIFY → ACT**

The design is both **snapshot-driven** and **event-driven**:

- Snapshot-driven discovery is authoritative. Complete snapshots find targets that an
  event stream missed and remove targets that no longer belong to the inventory.
- Event-driven signals are hints that can move likely changes ahead of the baseline
  queue. A signal never proves current ownership or exposure by itself.
- Periodic reconciliation compares complete snapshots, repairs missed or duplicated
  events, and keeps the baseline sweep moving.

> **The sweep continues. The change jumps the line.**

## The model

- A **Target** is an authorized provider resource and network address eligible for
  verification. It has a stable identity, an ownership record, and a monotonic
  generation.
- An **Exposure** is outside-vantage evidence about whether a transport/port on a Target
  was reachable at a specific time. Missing, expired, failed, or incomplete evidence is
  **UNKNOWN**—never silently “closed.”
- A **Finding** is a policy-relevant interpretation of one or more Exposures plus current
  context. A Finding is not the raw scanner output.

Inventory and prior evidence classify each door:

- **new door** (`new_target`): a Target first discovered, or reactivated after its
  previously accepted state was removed;
- **changed door** (`target_change`): an active known Target whose address binding or
  scan-relevant non-policy lifecycle state changed;
- **changed door** (`policy_change`): an active known Target whose attached security
  groups or effective ingress policy changed; and
- **known door** (`coverage`): an unchanged Target that remains in the periodic
  reconciliation sweep.

New and changed doors receive priority. Known doors retain scheduled coverage so an
event path cannot starve the baseline.

## How the lifecycle works

1. **DISCOVER** — a provider adapter reads a complete inventory snapshot. Optional
   control-plane signals identify resources worth rereading sooner.
2. **PRIORITIZE** — policy assigns a profile, priority, rate class, and deadline to each
   new door, changed door, or known door.
3. **VERIFY** — immediately before dispatch, the system rereads current provider state
   and revalidates that the address is still owned by the expected Target generation.
   An outside-vantage worker then performs the authorized scan.
4. **ACT** — normalized evidence updates Exposure state. Detection policy may open,
   update, or resolve a Finding; inconclusive work remains UNKNOWN and is retried or
   reconciled.

Ownership revalidation is a hard dispatch gate. This matters for recycled public
addresses: a queued Target can become stale between discovery and scanning. A stale,
moved, missing, or ambiguous ownership verdict must not be scanned.

## First public release scope

The first release is intentionally narrow:

- self-hosted deployment in AWS;
- a single AWS account by default, with an optional hub/spoke pattern;
- complete snapshots of supported AWS resources with public IPv4 addresses;
- optional AWS-native change signals treated only as acceleration hints;
- bounded Nmap jobs orchestrated on Kubernetes from an outside vantage;
- durable queues, idempotency records, object evidence, and relational state; and
- provider-neutral source and evidence contracts intended for additional adapters.

The first release does **not** promise a p95 detection time or any universal latency
SLO. End-to-end time depends on provider freshness, snapshot cadence, queue depth,
profile, rate limits, target behavior, and scanner placement. Operators must measure
their own environment.

The first release also excludes:

- Internet-wide or third-party scanning;
- private-address or IPv6 scanning;
- production-ready Azure or Google Cloud adapters;
- automatic remediation or enforcement;
- a hosted control plane, turnkey organization rollout, or compliance certification;
- guarantees that an open service is vulnerable, or that no observed port means a host
  is safe.

Only scan assets you own or are explicitly authorized to test. Start with
[scanning safety](docs/scanning-safety.md).

## Repository layout

- `contracts/` and `schemas/`: versioned TargetEvent, ScanResultEnvelope, and Finding
  wire contracts.
- `inventory/`: AWS Config/direct-EC2 snapshots, CloudTrail signal resolution,
  generation state, ownership revalidation, and the transactional outbox.
- `generator/`: freshness-gated dispatch into one-shot Scanner resources.
- `operator/`: the Kubernetes controller, CRD, Helm chart, and hardened Job policy.
- `scanner/nmap/`: the single-target Nmap worker and immutable evidence publisher.
- `parser/`, `processor/`, and `db/`: generation-safe Exposure state, generic rules,
  Findings, handoff, and migrations.
- `terraform/aws/`: staged single-account deployment and optional hub/spoke onboarding.

## Validate and deploy

Python 3.12 and `uv` are required for the local workspace:

```bash
make sync
make check
make test-go
make vet-go
```

`make ci` adds offline Terraform and Kubernetes rendering. `make containers` builds all
seven images. Deployment is intentionally staged with dispatch disabled until images,
migrations, the operator, and an authorized canary are ready; follow the
[AWS deployment guide](docs/aws-deployment.md).

## Documentation

- [Architecture](docs/architecture.md)
- [AWS deployment](docs/aws-deployment.md)
- [Configuration](docs/configuration.md)
- [Operations](docs/operations.md)
- [Security model](docs/security-model.md)
- [Scanning safety](docs/scanning-safety.md)
- [Data handling](docs/data-handling.md)
- [Testing](docs/testing.md)
- [Costs](docs/costs.md)
- [Multi-account deployment](docs/multi-account.md)
- [Adding inventory or signal sources](docs/adding-sources.md)

## Project status

The project is pre-1.0. Treat contracts, migrations, deployment manifests, and container
images as a coordinated release. Review the staged activation procedure before using a
real account.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and review requirements and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.
