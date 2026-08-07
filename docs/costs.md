<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Costs

Portscanner has no universal cost estimate. Inventory volume, snapshot cadence, change
rate, scan profile, network path, evidence retention, database choice, and cluster
utilization dominate the result. Use current provider pricing for the selected Regions.

## Cost drivers

### Inventory and signals

- provider inventory/configuration recording and queries;
- API request and pagination volume;
- trail or event-bus ingestion, archive, and delivery;
- cross-account or cross-Region event forwarding; and
- queue requests and dead-letter retention.

Reusing an existing Config or CloudTrail setup may reduce duplicate collection, but it
can also add charges to a shared service. Confirm ownership and marginal cost. Do not
create a duplicate organization trail by default.

### Scheduling and orchestration

- serverless invocations and duration;
- lease/idempotency reads and writes;
- standard-resolution CloudWatch metric alarms;
- Kubernetes control plane, nodes, autoscaling floor, and logs; and
- container registry storage and vulnerability scanning.

Priority capacity should share a bounded pool with periodic reconciliation. Permanent
overprovisioning for a rare burst is usually more expensive than a measured queue-age
budget.

The application creates 12 storage alarms (six primary queues and six dead-letter
queues). Deploying the ten Lambda functions adds 20 error/throttle alarms and one
outbox iterator-age alarm, for 33 total. These are standard-resolution metric alarms
and are usually a small low-single-digit monthly charge at common regional prices, but
use current CloudWatch pricing for the deployment Region. Externally managed SNS,
paging, and notification delivery can add separate charges.

### Network verification

A rough probe-volume model is:

```text
probes per cycle
  = targets
  × selected ports
  × transports
  × attempts/retries
```

Actual packets are higher because discovery, handshakes, service detection, scripts,
timeouts, and retransmission differ by profile. Data-transfer charges depend on scanner
placement and return traffic. Full-port, UDP, service-detection, and script profiles
must be estimated separately.

### Data

- raw evidence object count, size, versions, and retention;
- database compute, storage, I/O, backups, and replicas;
- logs, metrics, traces, and search/index retention;
- encryption-key requests; and
- cross-Region replication or disaster recovery.

Raw scanner output and verbose logs can outgrow normalized state. Apply retention,
compression, and log redaction deliberately; do not discard evidence required for
correct UNKNOWN or Finding lifecycle handling.

## Estimation worksheet

For each source, measure or estimate:

1. supported resources per complete snapshot;
2. pages and API calls per snapshot;
3. snapshots per day;
4. relevant signals per day and duplicate ratio;
5. new, changed, and known Targets per day;
6. ports, attempts, expected duration, and evidence size by profile;
7. peak and average concurrent Jobs;
8. queue, object, database, and log retention; and
9. cross-account/Region data paths.

Model baseline and priority traffic independently:

```text
daily work
  = periodic known-door work
  + deduplicated new/changed-door work
  + bounded retries
```

Then apply current service prices and a safety margin. Validate the model with a
low-rate authorized canary before increasing scope.

## Single-account versus hub/spoke

Single-account deployment minimizes trust and forwarding resources but duplicates
control planes if each account operates independently.

Hub/spoke deployment can consolidate Kubernetes, database, and evidence services. It
adds assume-role calls, event forwarding, centralized egress, larger failure domains,
and possible cross-account/Region transfer. A hub is not automatically cheaper; compare
both models at expected scale.

## Cost controls

- dispatch defaults off and authorization lists default empty;
- cap accounts, Regions, Targets, ports, retries, packet rates, and concurrent Jobs;
- reserve baseline capacity without creating an unbounded priority fleet;
- coalesce signals by Target and generation;
- expire stale work before resource creation;
- autoscale workers with explicit minimum and maximum;
- use object lifecycle and database retention;
- sample high-volume debug logs and exclude raw evidence from logs;
- set provider budgets and anomaly alerts outside this public repository; and
- tag project-owned resources with a non-sensitive cost-allocation label.

## Cost alarms

Alert on:

- inventory request or event-delivery spikes;
- queue redrive loops;
- scan attempts per effective Target;
- worker-hours with no accepted evidence;
- object version growth;
- database I/O/storage deviation;
- log ingestion deviation; and
- resources remaining after sandbox cleanup.

Cost pressure must not be handled by treating missing evidence as closed. Reduce cadence
or scope explicitly and expose the resulting UNKNOWN/coverage gap.
