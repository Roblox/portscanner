<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# AWS deployment

This guide describes the first-release AWS deployment model. It is a staged procedure,
not a promise that one Terraform apply can safely adopt every existing account.

Read [scanning-safety.md](scanning-safety.md), configure the mandatory account gate and
any optional CIDR defense, and obtain written authorization before creating scanner
capacity.

## Deployment modes

### Single-account default

The default places inventory readers, queues, idempotency records, Kubernetes
orchestration, evidence storage, and relational state in one AWS account. Use this mode
for an evaluation and for an account whose public assets can be governed by one owner.

The scanner still needs an outside vantage: packets must reach the target through its
publicly routed edge, not through a private address or an internal load-balancer path.

### Optional hub/spoke

A hub can own scheduling, scanning, evidence, and state while spoke accounts either:

- expose a least-privilege read role that the hub assumes for snapshots and
  current-state ownership checks; or
- forward normalized change notifications to the hub, with a read role retained for
  authoritative rereads.

Signals alone are insufficient. The hub must be able to obtain complete snapshots and
revalidate ownership immediately before dispatch. See [multi-account.md](multi-account.md).

## Clean account and existing-service choices

Record each choice before planning Terraform. Do not let an evaluation overwrite
account-wide services.

### AWS Config

- **Clean-account mode:** set `config_mode = "create"` so the application creates the
  recorder, delivery channel, aggregation/query resources, required bucket policy, and
  same-account aggregation authorization. One module instance records only its provider
  Region, so the created aggregator explicitly includes that Region rather than claiming
  all-Region coverage. Each additional member account in that same source Region must
  run the member module there and authorize the exact central account and aggregator
  Region before the central aggregator includes it. For other source Regions, use
  direct EC2 snapshots or an existing aggregator whose per-Region recorders and
  authorizations are provisioned outside this one-provider module instance.
- **Existing Config mode:** set `config_mode = "existing"` and provide
  `existing_config_aggregator_name`; the adapter receives narrow query/read
  permissions. Verify every intended account/Region has a healthy recorder and source
  authorization for that aggregator. AWS Config has account/Region singleton constraints;
  a second recorder or delivery channel can fail or disrupt established collection.
- **No Config mode:** set `config_mode = "disabled"` and configure the direct EC2
  paginated snapshot backend. Keep periodic reconciliation; a CloudTrail event stream
  is not a replacement for inventory.

### CloudTrail and change signals

- **Clean-account mode:** without `existing_cloudtrail_arn`, Terraform creates a
  multi-Region management trail. The narrowly filtered EventBridge routes remain paused
  through earlier stages and receive only events emitted in the Terraform provider
  Region; a multi-Region trail does not make one regional EventBridge rule global.
- **Existing CloudTrail mode:** provide `existing_cloudtrail_arn` for a validated
  multi-Region management trail rather than creating a duplicate trail.
- **Signals disabled:** this is fully supported. Snapshot-driven discovery and
  reconciliation remain authoritative.

For hot-path signals in another Region, deploy a uniquely named member forwarding root
in that account and Region, pointing it at the central bus. It must create or explicitly
reference a member/organization multi-Region management trail. Periodic Config or direct
EC2 snapshots remain authoritative in every onboarded Region even when no forwarding
root is deployed there.

Do not enable broad data-event logging merely for this project. Review duplicate trail,
archive, event-bus, and delivery costs before activation.

### VPC and Kubernetes

- **Managed VPC mode:** set `create_vpc = true`; Terraform creates dedicated public NAT,
  private workload, and isolated database subnets plus controlled routing/endpoints.
  `vpc_cidr` must be a canonical AWS IPv4 network from `/16` through `/24`, leaving four
  subnet bits for valid AWS subnets.
- **Existing VPC mode:** set `create_vpc = false` and provide the existing VPC and
  subnet IDs through protected variables. The module validates VPC membership,
  availability-zone spread, public-IP behavior, route shape, and that both VPC DNS
  support and DNS hostnames are enabled, without taking ownership of the shared network.
  It also requires
  `existing_private_subnet_egress_mode`: every private route table must have a matching
  NAT-gateway or transit-gateway default route, or `vpc_endpoints` must provide explicit
  endpoint IDs for Config, DynamoDB, EC2, ECR API/DKR, EKS, EKS Auth, Logs, S3, Secrets
  Manager, SQS, and STS. Terraform verifies each endpoint is available, in the selected
  VPC, and exposes the expected regional service. Interface endpoints must have private
  DNS and an explicitly selected attached security group; Terraform manages TCP/443
  ingress to that group from the application Lambda and EKS workload security groups.
  The S3 and DynamoDB gateway endpoints must be associated with every selected private
  route table. AWS China names are checked per service because required endpoints use a
  mix of `com.amazonaws` and `cn.com.amazonaws` prefixes. Review endpoint policies
  separately because network reachability does not prove that a policy permits every
  required API action.

The first release's application module creates its EKS cluster. Adopting an unrelated
existing cluster is not a documented deployment mode.

Confirm that egress has a stable, documented source, packet rates can be limited, return
traffic is allowed, and the path genuinely exercises the public edge.

### Target authorization

`authorized_account_ids` is the mandatory inventory and dispatch boundary, and
activation still fails when it is empty. The generator must reread current provider
state and receive an unambiguous `ACTIVE` ownership verdict immediately before creating
scanner work.

`allowed_target_cidrs` and `denied_target_cidrs` are optional sets of canonical IPv4
prefixes. Terraform passes them through the EKS module and Helm to the operator, which
adds nonempty lists to scanner Jobs as deployment policy. Scanner-enforced denies apply
first. An empty allowlist means no additional CIDR restriction; it does not bypass the
account or current-ownership gates.

CIDR allowlisting is useful defense-in-depth for fixed Elastic IP ranges, but is often
impractical for dynamic public addresses. It is not part of a `Scanner` resource or
user event, and matching a prefix never authorizes scanning a third party.

## Prerequisites

- Terraform and the provider versions pinned by the repository;
- an AWS deployment role obtained through short-lived credentials or OIDC;
- Git, the AWS CLI, Docker buildx, `jq`, and Python 3 for the image publication
  helper;
- the AWS CLI on every migrate/install/activate runner, because Helm refreshes EKS
  credentials with `aws eks get-token`;
- a remote Terraform backend with locking and restricted access;
- a container registry and immutable image-digest policy;
- a Kubernetes cluster or approval to create one;
- a supported PostgreSQL service and an isolated migration identity;
- an authorization record covering every account, Region, any optional CIDR
  constraints, rate, port profile, and test window; and
- repository/environment variables for account-specific values. Never commit account
  numbers, role ARNs, resource IDs, state, or variable files.

## Staged activation

Use separate reviewed plans for each stage. Preserve the plan output and deployment
identity in the change record. The public helper accepts `foundation`, `runtime`,
`migrate`, or `activate`:

```bash
terraform/aws/scripts/deploy.sh "${TF_ROOT}" foundation
```

The stages map to four explicit application flags:

- `deploy_runtime`;
- `run_migration`;
- `install_operator`; and
- `enable_event_dispatch`.

The foundation keeps all four false. All examples contain synthetic defaults and expose
names, accounts, VPC/subnets, member maps, API-client security groups, and installer
principals as variables. Supply live values, `image_digests`, and `migration_checksum`
through a reviewed ignored private variable file, never by editing or committing an
example.

### 1. Plan foundations with all producers disabled

Create or reference encryption keys, buckets, queues, dead-letter queues, lease storage,
database networking, and the Kubernetes control plane. Keep snapshot publication,
signal consumption, dispatch, and recurring scans disabled.

Run:

```bash
terraform -chdir="${TF_ROOT}" init
terraform -chdir="${TF_ROOT}" plan -out="${PLAN_FILE}"
terraform -chdir="${TF_ROOT}" show "${PLAN_FILE}"
```

Reject any plan that replaces an existing Config recorder, trail, VPC, database,
cluster, or shared policy unexpectedly.

### 2. Build, scan, and publish immutable images

Build each component from the reviewed commit, run its unit and contract tests, scan the
image, generate provenance where supported, and publish by digest. Record the digest;
do not deploy a mutable tag such as `latest`.

Lambda images must remain single-architecture image manifests. The repository helper
therefore emits attached BuildKit attestations only for the EKS operator/scanner images;
release CI should retain Lambda SBOM and provenance as separate artifacts.

Terraform creates repositories but never builds images. Populate every required
`image_digests` entry with an immutable `sha256:` digest before the runtime stage.

Set the same application or example root used for the foundation apply. First run the
side-effect-free validation path:

```bash
export TF_ROOT="terraform/aws/examples/created-vpc"
terraform/aws/scripts/build-images.sh --dry-run "${TF_ROOT}" arm64
```

Dry run validates the central root, clean source gate, tooling, applied repository and
deployment-state outputs,
repository URL shape, all seven Dockerfile/context mappings, and the migration
checksum. It does not call AWS, log in, build, push, or print a digest block. Use
`PORTSCANNER_ALLOW_DIRTY=true` only when locally testing the helper itself, never for a
release build.

For an ARM deployment, `arm64` maps to `linux/arm64`,
`lambda_architecture = "arm64"`, and `node_ami_type =
"AL2023_ARM_64_STANDARD"`. For x86, `x86_64` maps to `linux/amd64`,
`lambda_architecture = "x86_64"`, and `node_ami_type =
"AL2023_x86_64_STANDARD"`. Every component in one deployment must use the same mapping.

With the reviewed commit checked out cleanly, Trivy installed, and the AWS identity and
Region configured, push all images and capture only the final HCL:

```bash
SOURCE_REVISION="$(git rev-parse HEAD)"
terraform/aws/scripts/build-images.sh \
  "${TF_ROOT}" arm64 "${SOURCE_REVISION}" \
  >"$HOME/portscanner-image-inputs.tfvars"
```

Inventory, generator, parser, processor, migrator, and scanner use the repository root
as their context; operator uses `operator/`. The helper passes `--pull` and the selected
platform, enables attached provenance/SBOM attestations for EKS images when buildx
supports them, authenticates once per exact ECR registry, pushes directly, and verifies
every returned `sha256:` digest. It accepts the application, created-VPC, existing-VPC, and central
multi-account roots at foundation or a valid later stage, so the same path supports
upgrades. It explicitly rejects the member root and rejects malformed stage ordering,
an account/Region mismatch, unsafe roots or tags, `latest`, and partial output. Before
building each component, it checks the architecture-scoped immutable commit tag and
reuses an existing valid digest. Only a successful ECR tagged-image listing that confirms absence permits a
build; lookup errors or malformed existing digests stop the run. A partially completed
seven-image publication can therefore be rerun without attempting to overwrite
immutable tags. Every reused or newly pushed digest must pass a fixable
HIGH/CRITICAL Trivy scan before the helper emits Terraform input. It never runs
Terraform apply or enables dispatch.

ECR count-based expiration is disabled. Optional lifecycle configuration expires only
untagged images; Terraform never expires tagged immutable releases. Operators must keep
every digest used by the active release and rollback window, then retire tags/images
through a separately reviewed release-retention process.

Progress is written to stderr, so stdout can be redirected safely. The destination is
chosen by the operator and must remain private and uncommitted; the helper does not
create a variable file. Review the resulting `image_digests` map and
`migration_checksum` before passing that file to the paused runtime stage. The checksum
covers sorted migration file names and bytes using the deterministic framing documented
in `terraform/aws/README.md`.

### 3. Apply runtime and IAM wiring, still paused

Apply service accounts, OIDC trust, least-privilege policies, queues, event targets, and
digest-pinned functions with `deploy_runtime = true`; keep migration, operator install,
event mappings, schedules, and dispatch off. Verify that each workload uses the expected
digest and that no static cloud credential exists in a Secret or image layer.

### 4. Run compatible migrations, then install the operator

Back up the database. The `migrate` stage sets `run_migration = true` with a
content-derived `migration_checksum`, passes that checksum to the migrator, requires the
response to verify the same value, and only then sets `install_operator = true`. The
private EKS API must be reachable from the approved runner for the Helm install.

Set `eks_installer_principal_arns` to stable IAM role/user ARNs (never STS session ARNs)
and `eks_api_client_security_group_ids` to the runner/VPN security groups. Terraform
creates EKS access entries with the cluster-scoped `AmazonEKSClusterAdminPolicy`; Helm
uses AWS CLI exec authentication, not a plan-cached token. Bootstrap creator admin is
disabled by default and is not an installer substitute. The runner credentials must
resolve to one of the explicit principals and have private network reachability.

Migrations must be transactional where supported, idempotently recorded, and tested
against both an empty database and the previously released schema. Do not run
destructive contraction in the same release. Remove obsolete columns or constraints
only after all old writers are gone and rollback is no longer required.

### 5. Activate snapshot collection

With event dispatch still false, invoke one read-only source in one Region. Validate
pagination, snapshot completeness, stable Target identities, monotonic generations,
metadata redaction, and expected removal behavior.

### 6. Activate a bounded canary

Enable dispatch only for an explicit account allowlist. For a fixed authorized address
range, add a small CIDR allowlist as defense-in-depth. Use the lowest rate and narrowest
profile. Verify ownership rereads, source vantage, deadline handling, evidence upload,
UNKNOWN behavior, and cleanup.

### 7. Add signals and periodic coverage

Run the `activate` stage only after the snapshot/canary checks. It sets
`enable_event_dispatch = true`, enabling the previously paused mappings, schedules, and
filtered signal rules. Confirm that a duplicate or reordered signal causes only an
idempotent reread and that known-door reconciliation retains reserved capacity.

### 8. Expand in reviewed increments

Add snapshot Regions, regional forwarding roots, accounts, optional CIDRs, and rates
independently. Do not describe another Region as hot-path covered until its forwarding
root and CloudTrail prerequisite are live. Observe queue age,
ownership-gate verdicts, scan error classes, evidence lag, and cost before each
expansion.

## Rollback

Disable signal intake and dispatch first; preserve inventory and evidence for diagnosis.
Roll workloads back to the prior image digests only while the expanded database schema
remains compatible. Do not reverse a migration that would discard evidence during an
incident.

After an evaluation, destroy project-created resources with the same Terraform state,
verify queue and object lifecycle cleanup, remove spoke trust, delete temporary
environment variables, and confirm that shared Config, CloudTrail, VPC, and cluster
resources were not changed.

Buckets retain versions and default to `force_destroy_buckets = false`. A disposable
sandbox that must clean itself up may explicitly set this variable to `true`; retained
or production environments should keep the default and use a reviewed evidence
retention/export procedure before destroy.

The manual sandbox workflow is intentionally inert until repository variables and an
approval-protected environment are configured. Its cleanup step runs with an
unconditional `always()` guard.
