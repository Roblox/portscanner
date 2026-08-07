<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Operations

Operate Portscanner as a safety-sensitive distributed system. Success is not merely
“Jobs completed”; it is complete inventory, current ownership, declared scan coverage,
durable evidence, and correctly preserved UNKNOWN state.

## Health signals

Monitor by source, account alias, Region, profile, and outcome without logging raw
account numbers or addresses.

### Discovery

- last complete snapshot time and duration;
- pages, Targets, upserts, unchanged Targets, and removals per snapshot;
- incomplete/aborted snapshot count;
- source freshness and throttling;
- duplicate and out-of-order signals;
- signal-to-current-state-reread latency; and
- known Targets not present in a recently accepted complete snapshot.

### Priority and ownership

- queue depth and oldest age by priority;
- baseline capacity actually served;
- expired work and lease contention;
- idempotency conflicts;
- ownership verdicts (`ACTIVE`, `STALE`, `MOVED`, `INACTIVE`, `UNKNOWN`);
- time between ownership reread and dispatch; and
- work suppressed by account, CIDR, profile, or rate gates.

### Verification and evidence

- Jobs pending, running, succeeded, failed, timed out, and evicted;
- packet/concurrency budget utilization;
- result envelopes missing, duplicated, malformed, or quarantined;
- declared coverage versus observed output;
- evidence upload and parse lag; and
- Exposure transitions, UNKNOWN age, and Findings by lifecycle state.

Do not publish a p95 objective until the deployment has a defined clock, scope,
exclusions, sufficient samples, and an alert policy. Provider freshness, queue time,
scan time, and parse time should be reported separately.

## Provisioned CloudWatch alarms

The AWS application creates alarms even when no notification actions are configured.
Storage always creates:

- `ApproximateAgeOfOldestMessage` for each primary SQS queue. The maximum age must
  reach `queue_age_alarm_threshold_seconds` (15 minutes by default) in two consecutive
  five-minute periods.
- `ApproximateNumberOfMessagesVisible` for each dead-letter queue. Any visible message
  in a one-minute period alarms.

When `deploy_runtime` is true, every Lambda function also gets an `Errors` alarm and a
`Throttles` alarm for one or more events in a five-minute period. The dedicated
inventory outbox function gets an `IteratorAge` alarm, using the stable Lambda
`FunctionName` dimension for its DynamoDB Streams mapping. Its maximum iterator age
must reach `iterator_age_alarm_threshold_seconds` (15 minutes by default) in two
consecutive five-minute periods. AWS reports that metric in milliseconds; Terraform's
input remains seconds.

All of these alarms treat missing data as not breaching. This avoids false alarms for
idle queues, disabled event sources, and functions with no invocations, but operators
must separately detect missing expected schedules or traffic. Use the application
`alarm_names` and `alarm_arns` outputs to inventory the resulting alarms.

### Attach notifications externally

The stack deliberately creates no SNS topic, email subscription, or organization-
specific paging integration. Pass existing action ARNs through `alarm_action_arns` and,
optionally, `ok_action_arns`. For example, an operator can supply the ARN of an
externally managed SNS topic whose subscriptions route to the team's paging system.
Empty lists leave every alarm active and visible without sending notifications.

Grant and test any required publish/invoke permissions in the external integration.
Route recovery notifications only when they are actionable; an `OK` transition does
not prove that queued work was processed successfully.

### Interpret and extend coverage

- Primary queue age means a producer/consumer imbalance, paused event source, failed
  downstream service, or deliberately unconsumed external handoff needs investigation.
- A dead-letter message means retries were exhausted or EventBridge delivery failed;
  inspect and preserve the message before redriving it.
- Lambda errors indicate failed invocations. Throttles indicate reserved concurrency or
  account concurrency prevented work from starting.
- Outbox iterator age means DynamoDB stream records are not being drained promptly,
  even if invocation errors are absent.

Lambda metrics do not observe scanner Kubernetes Job failures after generator work is
accepted. The SQS age alarms cover queue backlog before consumption, but do not prove
that a scanner Job completed or that evidence arrived. Add environment-specific
Kubernetes/Container Insights dashboards, Prometheus alerts, or log metric filters for
Jobs failed, timed out, or stuck, and correlate them with queue age and missing result
envelopes.

## Normal operating checks

Daily:

1. Confirm each enabled source has a recent complete snapshot.
2. Confirm known-door reconciliation is advancing while priority work is present.
3. Review dead-letter queues, quarantine, UNKNOWN age, and ownership-gate failures.
4. Compare dispatched work with immutable result envelopes and parsed records.
5. Check rate, cost, and Kubernetes capacity guardrails.

After every deployment:

1. Record deployed image digests and migration version.
2. Verify feature gates and authorization policy digest.
3. Run a non-network contract check, then one approved canary.
4. Confirm duplicate canary delivery is idempotent.
5. Confirm a deliberately expired item and stale generation do not dispatch.
6. Verify cleanup and retention behavior.

## Runbooks

### Snapshot is late or incomplete

1. Disable removal application for the affected source; never infer deletion from a
   partial page walk.
2. Check provider throttling, pagination cursor handling, role access, Region selection,
   and source-data freshness.
3. Retry the full snapshot with bounded backoff.
4. Accept removals only after one complete, validated snapshot commits atomically.
5. Reconcile queued work against the newly accepted generation.

### Signal backlog grows

Signals only accelerate work. Preserve snapshot and periodic queues, reduce signal
intake if necessary, and coalesce by stable Target identity. For each surviving hint,
reread current state before scheduling. Do not replay stale signal payloads as inventory.

### Ownership UNKNOWN increases

Pause dispatch for the affected source. Check provider API availability, credentials,
throttling, eventual-consistency windows, and adapter parsing. Retry within the work
deadline. If current ownership cannot be proved, leave work suppressed and Exposure
state unchanged.

### Scanner failures increase

Pause the affected profile, not the inventory path. Check image digest, Kubernetes
events, resource limits, network egress, DNS, raw-socket capabilities, destination rate
limits, and timeout classes. A failed or incomplete scan remains UNKNOWN and must not
resolve Findings.

### Parser or database is unavailable

Stop result deletion and preserve the object/queue source of truth. Increase visibility
timeout if needed, avoid parallel replay beyond database capacity, and restore parsing
with the same idempotency keys. Confirm that replay creates no duplicate Exposure or
Finding transitions.

### Authorization boundary changes

Disable dispatch first. Update the external authorization record, account/CIDR gates,
and provider policy together. Reconcile queued work and discard anything outside the
new boundary. Re-enable only after an ownership-gated canary.

## Backup and recovery

- Version object evidence and apply lifecycle retention deliberately.
- Back up relational state before migrations and test point-in-time recovery.
- Keep Terraform state encrypted, locked, access-logged, and outside the repository.
- Treat queue retention and dead-letter retention as part of the recovery-point
  objective.
- Restore into an isolated environment with dispatch disabled.
- Reconcile provider snapshots after restore; do not blindly replay old scan work.

## Upgrades

Follow the staged order in [aws-deployment.md](aws-deployment.md): foundations,
expand-only migrations, tested image digests, disabled wiring, source activation,
bounded canary, then wider activation. Keep old readers and writers schema-compatible
during rollback.

Generated manifests must be regenerated by the documented command and checked for drift
in CI. Never hand-edit a generated artifact without updating its source.

## Decommission and cleanup

1. Disable signals, scheduling, and dispatch.
2. Drain or explicitly discard queues and record the decision.
3. Export required audit/evidence data, then apply retention and deletion policy.
4. Destroy project-owned infrastructure from its Terraform state.
5. Remove hub/spoke trust, event-bus permissions, OIDC subjects, registry images, DNS,
   and Kubernetes service accounts.
6. Verify shared Config, CloudTrail, VPC, cluster, and database resources remain intact.
7. Revoke the scanning authorization and document completion.
