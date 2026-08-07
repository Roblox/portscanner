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
  recorder, delivery channel, aggregation/query resources, and required bucket policy.
- **Existing Config mode:** set `config_mode = "existing"` and provide
  `existing_config_aggregator_name`; the adapter receives narrow query/read
  permissions. AWS Config has
  account/Region singleton constraints; a second recorder or delivery channel can fail
  or disrupt established collection.
- **No Config mode:** set `config_mode = "disabled"` and configure the direct EC2
  paginated snapshot backend. Keep periodic reconciliation; a CloudTrail event stream
  is not a replacement for inventory.

### CloudTrail and change signals

- **Clean-account mode:** without `existing_cloudtrail_arn`, Terraform creates a
  multi-Region management trail and narrowly filtered event routes. Event dispatch
  remains paused through earlier stages.
- **Existing CloudTrail mode:** provide `existing_cloudtrail_arn` for a validated
  multi-Region management trail rather than creating a duplicate trail.
- **Signals disabled:** this is fully supported. Snapshot-driven discovery and
  reconciliation remain authoritative.

Do not enable broad data-event logging merely for this project. Review duplicate trail,
archive, event-bus, and delivery costs before activation.

### VPC and Kubernetes

- **Managed VPC mode:** set `create_vpc = true`; Terraform creates dedicated public NAT,
  private workload, and isolated database subnets plus controlled routing/endpoints.
- **Existing VPC mode:** set `create_vpc = false` and provide the existing VPC and
  subnet IDs through protected variables. The module validates VPC membership,
  availability-zone spread, public-IP behavior, and route shape without taking
  ownership of the shared network.

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

The foundation keeps all four false. Supply account-specific values, the
`image_digests` map, and `migration_checksum` through a reviewed private variable file,
never through a committed example.

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

Dry run validates the root, clean source gate, tooling, paused foundation outputs,
repository URL shape, all seven Dockerfile/context mappings, and the migration
checksum. It does not call AWS, log in, build, push, or print a digest block. Use
`PORTSCANNER_ALLOW_DIRTY=true` only when locally testing the helper itself, never for a
release build.

For an ARM deployment, `arm64` maps to `linux/arm64`,
`lambda_architecture = "arm64"`, and `node_ami_type =
"AL2023_ARM_64_STANDARD"`. For x86, `x86_64` maps to `linux/amd64`,
`lambda_architecture = "x86_64"`, and `node_ami_type =
"AL2023_x86_64_STANDARD"`. Every component in one deployment must use the same mapping.

With the reviewed commit checked out cleanly and the AWS identity and Region configured,
push all images and capture only the final HCL:

```bash
SOURCE_REVISION="$(git rev-parse HEAD)"
terraform/aws/scripts/build-images.sh \
  "${TF_ROOT}" arm64 "${SOURCE_REVISION}" \
  >"$HOME/portscanner-image-inputs.tfvars"
```

Inventory, generator, parser, processor, migrator, and scanner use the repository root
as their context; operator uses `operator/`. The helper passes `--pull` and the selected
platform, enables provenance and SBOM attestations when buildx supports them,
authenticates once per exact ECR registry, pushes directly, and verifies every returned
`sha256:` digest. It refuses a non-foundation deployment state, an account/Region
mismatch, unsafe roots or tags, `latest`, and partial output. It never runs Terraform
apply or enables dispatch.

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
content-derived `migration_checksum`, waits for the expand-only migration, and only then
sets `install_operator = true`. The private EKS API must be reachable from the approved
runner for the Helm install.

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

Add Regions, accounts, optional CIDRs, and rates independently. Observe queue age,
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
