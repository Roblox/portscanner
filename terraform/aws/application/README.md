# Central application module

This module composes the portable AWS foundation and runtime. Use it from a root under `../examples` so the root configures the AWS provider without a developer profile.

The four deployment switches default to false:

- `deploy_runtime`
- `run_migration`
- `install_operator`
- `enable_event_dispatch`

Checks reject skipped stages, missing image digests, malformed migration checksums, empty activation scope, and account scopes not authorized by the central event bus. Lambda mappings and schedules are created disabled during the runtime stage. The Helm release consumes a token that is unknown until the keyed `aws_lambda_invocation` succeeds.

The application secret is created without a value. The migrator reads the RDS-managed master secret, creates or rotates the least-privilege database user, and writes only the application credential to that secret. Secret material is not supplied as a Terraform variable.

Runtime wiring uses:

- one inventory table for target state, transactional outbox entries, and signal dedupe, plus one dispatch/idempotency table;
- signal, priority, coverage, target-event, result, and external finding queues, each with a DLQ;
- an inventory-stream outbox Lambda that writes immutable target events and routes their S3 notification envelopes;
- a target projector and result parser with private Aurora access;
- a scheduled finding reconciliation processor with no SQS event source; and
- the repository Helm chart at `operator/chart/portscanner`, with Scanner-only generator RBAC owned by that chart.

The results notification is restricted to `results/**/scan-result.json`. Finding notifications are restricted to `findings/` and are intended for an external handoff consumer. Every PostgreSQL runtime reads only the migrator-populated application secret; only the migrator can read the master secret or write the application secret.

When `config_mode` is `create` or `existing`, snapshot schedules query the configured aggregator with explicit account scopes. `disabled` selects direct EC2 collection and requires `snapshot_regions` (the deployment region is the default). A referenced existing aggregator is not introspected, so its account authorizations, region coverage, recorder state, and freshness remain live deployment prerequisites.

Cost and destruction warning: the foundation includes NAT, EKS, a managed node group, Aurora, S3, SQS, DynamoDB, Config/CloudTrail, ECR, and logs. Production must enable database deletion protection, final snapshots, DynamoDB PITR, resilient NAT/nodes/database instances, and policy-appropriate retention. Data stores intentionally do not force-delete.
