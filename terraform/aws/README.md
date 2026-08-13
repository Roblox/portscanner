<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# AWS deployment

This directory deploys the complete AWS-hosted Portscanner pipeline:

`EC2 inventory → DynamoDB outbox → S3/SQS → generator → EKS/Helm/Nmap → S3/SQS → parser → Aurora PostgreSQL`

The default is a one-target evaluation. Periodic inventory, signal hints, and
finding export remain disabled until explicitly configured.

## Before you deploy

Use a dedicated AWS sandbox and review the plan. Even while scanning is paused,
EKS, Aurora, a NAT gateway, an EC2 canary, logs, and retained data incur
charges.

The bootstrap checks for:

- Terraform 1.7.4;
- AWS CLI v2 credentials for the exact deployment account and Region;
- Docker with Buildx, Trivy, `jq`, Python 3, Git, and `tar`; and
- a clean committed checkout so published image digests identify reviewed
  source.

The deployer needs permission to create the VPC, IAM, EKS, EC2, ECR, Aurora,
S3, SQS, DynamoDB, KMS, Secrets Manager, Lambda, EventBridge, Config,
CloudTrail, CloudWatch, and state resources selected by the environment file.
Use a stable IAM role or user ARN for EKS access, not an STS assumed-role ARN.

## One environment file

Copy the tracked template:

```sh
cp terraform/aws/deployment/environment.auto.tfvars.json.example \
  terraform/aws/deployment/environment.auto.tfvars.json
$EDITOR terraform/aws/deployment/environment.auto.tfvars.json
```

The ignored JSON file is the only user-maintained deployment configuration.
It contains no credentials. Set:

- the environment name, AWS account, and Region;
- the stable EKS installer principal and the Terraform runner's public `/32`;
- VPC, architecture, capacity, rate, and retention policy;
- whether the managed canary is present; and
- explicit integration account, CIDR, ENI class, and opt-in tag scope.

AWS credentials stay in the normal CLI/provider credential chain. Database
passwords are RDS/Secrets Manager managed. Backend and immutable image inputs
are generated under ignored `.portscanner/` storage with mode `0600`.

## Deploy and evaluate

Run:

```sh
./terraform/aws/scripts/bootstrap.sh
./terraform/aws/scripts/deploy.sh evaluate
```

Bootstrap:

1. verifies tools, the live STS account/Region, configuration shape, and clean
   source;
2. creates or verifies an encrypted S3 backend and DynamoDB lock table;
3. applies a saved, explicitly confirmed foundation plan with dispatch off;
4. builds all seven images for one architecture, scans every immutable digest,
   and pushes them to the environment's ECR repositories; and
5. writes generated digest and migration-checksum inputs atomically.

It is resumable and refuses state, backend, account, Region, or image
collisions.

Evaluation then:

1. creates the digest-pinned Lambda runtime with event sources paused;
2. runs the checksum-locked database baseline and installs the Helm operator;
3. enables only the one-target canary path;
4. snapshots the Terraform-owned EC2 ENI and scans only TCP 18080;
5. verifies one complete attempt, one open exposure, and one low PostgreSQL
   finding;
6. replays the snapshot to prove one-event/one-attempt idempotency; and
7. returns all dispatch and reconciliation controls to `pause-canary`.

Every Terraform apply still uses a displayed saved plan and an exact
confirmation. A single shell command does not mean hidden approval.

The canary is a tiny instance/EIP in a separate, unpeered VPC. It has no SSH
key, instance role, or general ingress/egress. TCP 18080 accepts traffic only
from the scanner NAT EIP. `localhost`, private addresses, and documentation
addresses are not runnable targets.

To install or repair the runtime without scanning:

```sh
./terraform/aws/scripts/deploy.sh ready
```

## Add AWS inventory

After evaluation, edit the same JSON:

1. add exact `authorized_account_ids` and `allowed_target_cidrs`;
2. retain deny-before-allow CIDR policy;
3. select supported ENI interface types;
4. require an opt-in ENI tag, such as `application=portscanner`; and
5. set `recurring_inventory_enabled` to `true`.

Direct EC2 snapshots are the simplest authoritative source:

```json
"config_mode": "disabled",
"snapshot_regions": ["us-east-1"]
```

Then review and activate:

```sh
./terraform/aws/scripts/deploy.sh activate
```

New and changed targets use explicit full-TCP policy. Do not broaden account,
CIDR, tag, rate, Pod, or Job limits without authorization and traffic review.
Periodic snapshots are authoritative; signal events only move likely changes
ahead of baseline coverage.

## Optional integrations

- **AWS Config:** choose `config_mode=create` or supply a reviewed existing
  aggregator. Existing mode cannot prove source accounts, Regions, recorder
  health, or freshness.
- **Signal hints:** set `signal_hints_enabled=true` and choose a reviewed
  CloudTrail mode. EventBridge/CloudTrail signals always resolve through a
  provider reread before dispatch.
- **Finding export:** set `finding_export_enabled=true` to add the versioned S3
  bucket, SQS/DLQ notification, IAM, and alarms. SQS messages point to S3
  objects; consumers must follow [the contract guide](../../contracts/README.md).
- **Multi-account:** use `examples/multi-account-central` plus
  `member-account`. Member roles trust exact central principals and an
  external ID; each hot-path Region needs its own reviewed forwarding root.
- **Existing VPC:** `examples/existing-vpc` validates subnet ownership, AZ
  spread, DNS, egress, endpoint identity/private DNS, and endpoint security
  groups. The canonical quickstart intentionally creates networking instead.

GCP, Azure, private-address, and IPv6 inventory are not production deployment
options in this release.

## Pause and emergency stop

Normal pause keeps infrastructure and evidence:

```sh
./terraform/aws/scripts/deploy.sh pause
```

A pause plan is accepted only when it disables managed event-source mappings
and EventBridge rules without changing images, migrations, Helm, or other
resources.

If Terraform or EKS refresh is unavailable:

```sh
./terraform/aws/scripts/emergency-pause.sh terraform/aws/deployment
```

Emergency pause uses exact controls from Terraform state. Neither pause method
terminates an already-created Kubernetes Job. Inspect and cancel active
Scanner/Job resources separately.

## Retire the canary

Pause first, wait for the pipeline to drain, set
`environment.managed_canary.enabled=false`, then run:

```sh
./terraform/aws/scripts/deploy.sh retire-canary
```

Retirement requires `kubectl`. It verifies all queues twice, requires every
Scanner and scanner Job to be terminal, proves no environment field other than
the canary switch changed, restricts the saved plan to the reviewed canary
boundary, and only then releases the EIP. Never release an EIP while queued or
active work can still reference it.

## Destruction and retained state

`destroy` is available only when the environment explicitly sets both
`disposable=true` and `destroy_data_on_teardown=true`:

```sh
./terraform/aws/scripts/deploy.sh destroy
```

It pauses first, displays a saved destroy plan, and requires typing
`destroy <environment-name>`. An installed deployment must also pass the same
queue, Scanner, and Job retirement-readiness checks before planning. State
bootstrap resources are deliberately left behind. Retained/non-disposable
environments should use deletion protection,
PITR, resilient nodes/database instances, one NAT per AZ, durable retention,
and a separately reviewed retirement procedure with a final database snapshot.

## Development

Terraform never builds images with provisioners or uses `-target`. Validate
the roots, modules, stage scripts, Helm chart, and generated artifacts from the
repository root:

```sh
make terraform-script-tests
make terraform-validate
make kubernetes-validate
make containers
```

No automated test scans a live address.
