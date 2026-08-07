<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Configuration

Configuration has two layers:

1. Terraform and environment configuration selects cloud resources, trust boundaries,
   and feature gates.
2. Versioned policy configuration selects authorized Targets, scan profiles, rates,
   deadlines, retries, and retention.

Secrets, account numbers, role identifiers, Terraform state, variable files, and
kubeconfigs must remain outside the repository.

## Required safety gates

Dispatch is permitted only when all gates agree:

- the source account is in the explicit account allowlist;
- the current provider object is in a supported resource class;
- current ownership revalidation returns `ACTIVE`;
- when a deployment CIDR allowlist is configured, the address is inside it;
- the address is not in a denylist or reserved range;
- the requested profile is approved for that source;
- the global, source, and destination rate budgets have capacity;
- the work deadline has not expired; and
- the deployment-wide dispatch feature gate is enabled.

An empty account allowlist blocks activation. An empty deployment CIDR allowlist adds no
CIDR restriction: the account gate and current ownership revalidation remain mandatory.
CIDR denies are evaluated before allows, and any CIDR parse error fails closed.

## Logical configuration

Deployments should expose these groups even if the concrete environment-variable names
differ.

### Source

- source identifier and adapter type;
- enabled accounts and Regions;
- snapshot cadence and maximum page duration;
- signal route enabled/disabled;
- adapter read-role reference supplied at deployment time;
- maximum source-data age;
- metadata field allowlist; and
- complete-snapshot timeout and retry budget.

### Scheduling

- priority classes for `new_target` (New door), `target_change` and `policy_change`
  (Changed door), and `coverage` (Known door);
- fast full-TCP policy for `target_change`, with a short deadline comparable to
  `policy_change`;
- explicit `manual` work labeled Manual verification;
- reserved baseline capacity;
- per-class queue age alarms;
- work deadline by profile;
- lease duration and heartbeat;
- maximum delivery attempts; and
- dead-letter destination.

### Scan policy

- allowed transports and ports;
- host, CIDR, and profile size limits;
- packet and concurrent-job rates;
- source and destination rate buckets;
- connect, host, and job timeouts;
- approved scanner arguments; and
- evidence completeness requirements.

Raw command fragments must not come from a Target, label, signal, or user-controlled
metadata. Select a named profile and construct arguments from typed fields.

### Data

- encryption key references;
- queue, object-store, and database endpoints;
- evidence and normalized-state retention;
- dead-letter and quarantine retention;
- log redaction mode; and
- whether raw evidence storage is enabled.

## First-release AWS mapping

Terraform exposes the deployment boundary in `terraform/aws/application`:

- `config_mode` (`create`, `existing`, or `disabled`) and
  `existing_config_aggregator_name`;
- `existing_cloudtrail_arn`;
- `create_vpc` plus existing VPC/subnet inputs;
- `authorized_account_ids`, `allowed_member_account_ids`,
  `member_collector_role_arns`, `allowed_target_cidrs`, and
  `denied_target_cidrs`;
- `snapshot_schedule_expression` (five minutes by default) and
  `rescan_schedule_expression` (six hours by default);
- `queue_age_alarm_threshold_seconds` and
  `iterator_age_alarm_threshold_seconds` (15 minutes by default);
- optional `alarm_action_arns` and `ok_action_arns`, both empty by default;
- `force_destroy_buckets`, disabled by default and intended only for disposable
  sandbox cleanup;
- `image_digests` and `migration_checksum`; and
- staged flags `deploy_runtime`, `run_migration`, `install_operator`, and
  `enable_event_dispatch`.

All scope collections default empty and all activation flags default false. Event
dispatch still requires nonempty `authorized_account_ids`; the target CIDR sets are
optional defense-in-depth. They are useful when authorization follows fixed Elastic IP
ranges, but are often impractical for dynamic public addresses.

Storage queue and dead-letter alarms are created regardless of action configuration.
Lambda error, throttle, and inventory-outbox iterator-age alarms are created only when
`deploy_runtime` creates the functions. Action values must be existing CloudWatch-
compatible action ARNs; the ARN-shape checks are partition-neutral and do not constrain
an account ID. Terraform does not create SNS, email, or paging resources. Integrate a
team-owned SNS/Pager path externally, then pass its action ARN if notifications are
wanted. The `alarm_names` and `alarm_arns` outputs contain no secrets.

Terraform passes target CIDRs through the EKS module and Helm as deployment policy. The
operator validates canonical IPv4 prefixes at startup and adds
`SCANNER_ALLOWED_CIDRS` or `SCANNER_DENIED_CIDRS` to scanner Jobs only for nonempty
lists. CIDRs are not fields in a `Scanner` resource or user event. Use the created-VPC,
existing-VPC, central multi-account, and member-account examples only as synthetic plan
fixtures; application examples pass no alarm actions, dispatch remains disabled by
default, and both CIDR sets may be empty.

The inventory runtime validates:

- `SNAPSHOT_BACKEND` as `config` or `ec2`;
- `CONFIG_AGGREGATOR_NAME` for Config snapshots;
- `AWS_ACCOUNT_ID` and `AWS_REGIONS` for direct EC2 snapshots;
- `DISCOVERY_ROLE_ARN_TEMPLATE` and `DISCOVERY_EXTERNAL_ID` for protected hub reads;
- `ALLOWED_TAG_KEYS` as a subset of the shared AWS metadata contract; and
- bounded `SIGNAL_DEDUPE_SECONDS`, `OUTBOX_TTL_SECONDS`,
  `RESCAN_BUCKET_SECONDS`, `MAX_SIGNAL_PORT_RANGES`, and `MAX_SIGNAL_PORTS`.

The generator separately validates queue/object, idempotency table, cluster, namespace,
lease, event-size, and audit-retention settings. Do not bypass those typed settings with
free-form scanner flags.

## Example policy

The following networks are documentation-only and non-routable. They demonstrate
the logical policy shape; this YAML is not consumed directly by the first-release
runtime and these networks are not scan targets. The `cidrs` list illustrates an
optional deployment constraint, not a substitute for the mandatory account and current
ownership gates.

```yaml
version: 1
dispatch_enabled: false

authorization:
  accounts:
    - "${ACCOUNT_ID}"
  cidrs:
    - "192.0.2.0/28"
    - "198.51.100.16/28"
  denied_cidrs:
    - "203.0.113.128/25"
  require_current_ownership: true

sources:
  - id: "aws-primary"
    adapter: "aws"
    regions:
      - "${AWS_REGION}"
    snapshot_interval: "30m"
    signals_enabled: false
    max_source_age: "15m"
    metadata_allowlist:
      - "environment"
      - "service"
      - "owner_ref"

profiles:
  priority:
    transports:
      tcp: [22, 80, 443]
    deadline: "10m"
    job_timeout: "5m"
    max_attempts: 2
  reconciliation:
    transports:
      tcp: [22, 80, 443]
    deadline: "2h"
    job_timeout: "15m"
    max_attempts: 2

rates:
  max_concurrent_jobs: 2
  max_packets_per_second: 100
  per_destination_packets_per_second: 20
  baseline_capacity_percent: 25

retention:
  raw_evidence_days: 30
  normalized_state_days: 180
  dead_letter_days: 14
```

IPv6 documentation may use only `2001:db8::/32`; IPv6 scanning is outside the first
release scope.

## Feature gates

Keep independently reversible gates for:

- snapshot collection;
- snapshot publication;
- signal intake;
- work creation;
- ownership revalidation;
- dispatch;
- result ingestion;
- finding emission; and
- recurring reconciliation.

No gate may bypass ownership or authorization checks. A canary gate narrows scope; it
does not weaken safety policy.

## Environment-specific values

Use repository or protected-environment variables for non-secret deployment references
and a cloud secret service for credentials. CI examples use names such as
`AWS_SANDBOX_ROLE_ARN`, `AWS_SANDBOX_REGION`, and `AWS_TERRAFORM_ROOT`; they intentionally
contain no live values.

Validate configuration in CI and again at process startup. Log a configuration digest
and safe feature-gate summary, but never render secret values, full provider payloads,
account numbers, or unredacted tags.
