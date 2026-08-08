# Portable AWS deployment

This tree deploys a portable, digest-pinned pipeline:

`AWS Config or EC2 snapshot + filtered EC2 hints -> inventory Lambda + single-table DynamoDB outbox -> immutable S3 target events -> generator and database projector Lambdas -> private EKS operator/Nmap jobs -> filtered S3 result notification -> parser Lambda -> private Aurora PostgreSQL`

EventBridge events are hints, not inventory truth. Periodic Config snapshots and rescans reconcile missed, duplicated, or reordered events.

Inventory state, transactional outbox rows, and signal dedupe markers share one `pk`/`sk` DynamoDB table. The outbox stream publishes immutable target-event objects and routes their S3 notification envelopes to priority, coverage, and database-projector queues. Generator claims use a separate `dispatch_id` table. Findings are immutable S3 handoffs; the finding queue notifies external consumers and is not consumed by the scheduled in-stack processor.

## Layout

- `state-bootstrap`: isolated S3/DynamoDB state bootstrap.
- `application`: central application module.
- `member-account`: independently deployable Config, collector role, and filtered event forwarding.
- `modules`: network, storage, database, EKS, ECR, identities, functions, and signal sources.
- `examples`: synthetic roots for created VPC, existing VPC, multi-account central, and member accounts.
- `scripts`: validation and staged deployment helpers.

All module sources and chart paths are repository-relative. Terraform never invokes Docker or builds an image. The examples expose names, accounts, networks, subnets, member maps, API client security groups, and installer principals as variables with only synthetic defaults. Override them from ignored private tfvars files before applying; do not edit tracked examples with live values.

## Staged deployment

Run from a central example root. `TF_BACKEND_CONFIG` points to an S3 backend file containing the bootstrap outputs and no credentials:

```sh
export TF_BACKEND_CONFIG="$PWD/backend.hcl"
export TF_ROOT="terraform/aws/examples/created-vpc"
terraform/aws/scripts/deploy.sh "${TF_ROOT}" foundation
```

The helper saves the reviewed plan and requires typing the stage name before applying it. Controlled automation must explicitly set `PORTSCANNER_AUTO_APPROVE=true`; the script rejects targeted, destroy, replacement, and refresh-only arguments.

The stages are intentionally one-way and explicit:

1. `foundation`: runtime, migration, Helm, and dispatch are disabled.
2. Build and scan all seven images in an external pipeline for the selected architecture, push them to the output ECR repositories, and record immutable `sha256:` digests.
3. `runtime`: create digest-pinned Lambda functions with mappings and schedules paused.
4. `migrate`: invoke the migrator keyed by its image digest plus migration checksum, then install the private-cluster Helm release.
5. `activate`: explicitly enable mappings, schedules, and filtered EventBridge rules.

After the foundation apply, validate the image mapping without contacting AWS or
building anything:

```sh
terraform/aws/scripts/build-images.sh --dry-run "${TF_ROOT}" arm64
```

The dry run still requires `git`, `terraform`, the AWS CLI, Docker buildx, `jq`, and
Python 3 to be installed, and it reads the applied `repository_urls` and
`deployment_state` outputs. It accepts only `application`, `created-vpc`,
`existing-vpc`, and `multi-account-central`; all export both outputs. It explicitly
rejects `member-account`. Valid foundation and later deployment states are accepted so
the same helper publishes upgrade images. Dry run makes no AWS identity call, registry
login, build, or push, and emits no digest input. A normal build additionally requires
a configured AWS Region and an authenticated identity in the exact account and Region
owning the output repositories, plus Trivy for the mandatory release-digest scan.

Build and push from a clean, reviewed checkout. The helper combines the checked-out
commit (or reviewed Git tag) with `arm64`/`x86_64`, so immutable ECR tags cannot be
reused across incompatible architectures. Redirect stdout to a private, non-committed
file; all progress is written to stderr:

```sh
SOURCE_REVISION="$(git rev-parse HEAD)"
terraform/aws/scripts/build-images.sh \
  "${TF_ROOT}" arm64 "${SOURCE_REVISION}" \
  >"$HOME/portscanner-image-inputs.tfvars"
```

The optional revision/tag must be Docker-tag safe, cannot be `latest`, and must resolve
to the checked-out `HEAD`. `PORTSCANNER_ALLOW_DIRTY=true` is accepted only with
`--dry-run`; deployment inputs always require a clean checkout. The helper
authenticates once per exact ECR registry using `aws ecr get-login-password`. Before
each build it checks the immutable commit tag: an existing valid digest is reused, while
a successful tagged-image listing that confirms absence is built and pushed. This makes
a partially completed seven-image publication safe to resume without overwriting
immutable tags. Any lookup error or malformed result fails closed. The helper removes
its temporary Docker authentication configuration and does not run Terraform init,
plan, or apply. It scans every reused or newly pushed immutable digest for fixable
HIGH/CRITICAL vulnerabilities and emits no Terraform input if any scan fails.

Inventory, generator, parser, processor, migrator, and scanner all use the repository
root as their build context. Only operator uses `operator/` as its context. The helper
uses `--pull`, the selected platform, and all seven exact Dockerfiles. It attaches
provenance and SBOM manifests only where the target runtime accepts them, as described
below.

Review the captured file before supplying it to the `runtime` and later stages. The
helper prints this deterministic shape only after every push and digest lookup succeeds;
it never creates a variable file itself:

```hcl
image_digests = {
  inventory = "sha256:<64 lowercase hex characters>"
  generator = "sha256:<64 lowercase hex characters>"
  parser    = "sha256:<64 lowercase hex characters>"
  processor = "sha256:<64 lowercase hex characters>"
  migrator  = "sha256:<64 lowercase hex characters>"
  operator  = "sha256:<64 lowercase hex characters>"
  scanner   = "sha256:<64 lowercase hex characters>"
}

migration_checksum = "<64 lowercase hex characters>"
```

The migration checksum is SHA-256 over every regular file directly in `db/migrations`,
sorted by UTF-8 file name. Each file name and file content is length-prefixed with an
eight-byte big-endian length before hashing, so both names and bytes affect the result
without ambiguous concatenation.

The private EKS API endpoint must be reachable from the machine running the migration/install stage, for example through an approved VPN or build runner in the VPC. Supply that runner or VPN security group through `eks_api_client_security_group_ids`; Terraform grants port 443 by security-group reference and never opens public endpoint ingress. Supply stable IAM role/user ARNs through `eks_installer_principal_arns`; Terraform creates EKS access entries and cluster-scoped `AmazonEKSClusterAdminPolicy` associations. Installation fails validation without both explicit paths. Bootstrap creator admin is disabled by default and does not replace them. The runner must have the AWS CLI because Helm refreshes credentials with `aws eks get-token`; no plan-cached token is used. The generator Lambda's private runtime security group is allowed automatically.

## Image architecture

The deployment deliberately uses one architecture for Lambda images, EKS nodes, the operator, and scanner. Passing `arm64` to the helper selects `linux/arm64` and must be paired with Terraform `lambda_architecture = "arm64"` and `node_ami_type = "AL2023_ARM_64_STANDARD"`. Passing `x86_64` selects `linux/amd64` and must be paired with `lambda_architecture = "x86_64"` and `node_ami_type = "AL2023_x86_64_STANDARD"`. Terraform rejects a Lambda/EKS architecture mismatch and queries EC2 instance-type metadata to reject node types that do not support the selected architecture.

Terraform only creates repositories and consumes digests. A typical external builder passes `--platform linux/arm64` (or `linux/amd64`) to BuildKit, verifies the image manifest architecture, scans the immutable artifact, and supplies the resulting digest. Lambda base images, the Go operator build, and the Debian scanner image all support explicit platform builds.

EKS defaults to Kubernetes 1.36 and also accepts 1.35. Those versions keep the
operator's Kubernetes 1.36 client libraries within supported minor-version skew.

The helper disables attached BuildKit provenance/SBOM manifests for the five Lambda
images so ECR stores the single-architecture image manifest Lambda expects. It enables
attached attestations for the operator and scanner images when BuildKit supports them.
Generate and retain separate SBOM/provenance artifacts for Lambda images in release CI;
do not change their deployed ECR digest into an attestation-bearing OCI index.

## Networking and production overrides

Created networking has public NAT subnets, private Lambda/EKS subnets, isolated Aurora subnets, and S3/DynamoDB gateway endpoints. Its canonical IPv4 VPC CIDR must be `/16` through `/24`, because the module adds four subnet bits and AWS subnets cannot be narrower than `/28`. The low-volume default uses one NAT gateway, one Spot node, one Aurora instance, conservative Lambda concurrency, short data retention, and no DynamoDB PITR. Production should normally override:

- `nat_gateway_mode = "one_per_az"`
- `node_capacity_type = "ON_DEMAND"` and a resilient node range
- `database_instance_count >= 2`
- `database_deletion_protection = true`
- `database_skip_final_snapshot = false`
- `dynamodb_point_in_time_recovery = true`
- backup, log, object, and queue retention
- reserved concurrency and schedule rates after load testing

Existing mode requires both VPC DNS support and DNS hostnames, and validates VPC membership, AZ spread, public-IP settings, absence of direct internet-gateway routes on private subnets, and absence of default routes on isolated subnets. It refuses to proceed without `existing_private_subnet_egress_mode`. NAT and transit modes require a matching default route from every private subnet. Endpoint mode requires explicit endpoint IDs for Config, DynamoDB, EC2, ECR API/DKR, EKS, EKS Auth, Logs, S3, Secrets Manager, SQS, and STS. Terraform verifies endpoint VPC, availability, expected service, interface private DNS, and S3/DynamoDB route-table associations. China endpoint names are validated per service because gateway and interface services use a mix of `com.amazonaws` and `cn.com.amazonaws` prefixes. Each interface endpoint also requires an explicitly selected attached security group; Terraform adds TCP/443 ingress from the application Lambda and EKS workload security groups. Review endpoint policies separately.

SQS visibility defaults to 360 seconds and must remain at least six times the queue-triggered Lambda timeout.

## Multi-account controls

The central custom bus policy uses an exact account allowlist unless an optional organization ID is supplied. No Organizations API or organization membership is required by default. Member accounts trust one exact central collector role with an external ID and grant only `ec2:Describe*`; event forwarding grants only `events:PutEvents` to one central bus ARN.

For direct member inventory, apply the central foundation first, use its `central_collector_principal_arns` output as each member's exact trusted principals, then feed each member's `collector_role_arn` output and paired external ID back through the central account-keyed maps. When any non-local scope is authorized, provide a collector entry for every authorized scope. Use one deterministic collector role path/name and one external ID across those accounts; Terraform derives the runtime's `{account_id}` role template while IAM remains restricted to the exact resulting ARNs. The snapshot and signal Lambdas may assume only those roles.

AWS Config can be created, disabled in favor of direct EC2 collection, or supplied as an existing aggregator. Snapshot schedules carry an explicit account scope. Create mode provisions its same-account source authorization and scopes the aggregator to the one provider Region where it creates a recorder; it never claims all-Region coverage from that recorder. Every member account in that same source Region must separately authorize the exact central account and aggregator Region before central apply. Other Config source Regions require direct EC2 snapshots or an externally provisioned existing aggregator. An existing aggregator is referenced by name only: Terraform cannot prove its source accounts, authorizations, recording regions, resource coverage, or freshness. Config is eventually consistent and only returns resources recorded in its configured sources, so retain periodic reconciliation and use the member collector role path where direct EC2 reads are required.

A multi-region management CloudTrail is always created centrally unless an existing trail ARN is supplied. Member API-event forwarding separately requires `cloudtrail_mode = "create"` or a referenced member/organization management trail. An ARN-only reference cannot prove selectors, logging health, or multi-region setting, so verify those live before activation. CloudTrail EventBridge rules exactly match the inventory runtime's EC2 API allowlist; separate rules also carry EC2 instance state-change hints. EventBridge is regional: the application `signal_region` and each member `signal_region` output identify the single hot-path Region covered by that module instance. Deploy uniquely named forwarding roots per additional Region and rely on authoritative snapshots elsewhere. All rules and runtime event mappings remain disabled until activation.

## Cost and destruction warning

Even idle environments incur charges for NAT gateways, Aurora, EKS, worker nodes, CloudTrail delivery, logs, and retained data. Review the plan and AWS pricing before applying.

Destruction is deliberately non-trivial: data buckets and ECR repositories do not force-delete, Aurora production safeguards are opt-in variables, and bootstrap state resources have `prevent_destroy`. ECR count expiration is disabled; optional lifecycle expiration affects only untagged images. Tagged active and rollback digests are release-operator-managed and must never be expired automatically. Drain queues, export findings, retain a final database snapshot, empty retained object versions, and remove bootstrap lifecycle protection only through a separately reviewed retirement change.

Only disposable test environments should set `force_destroy_buckets = true`; this is
needed for unattended cleanup after Config or CloudTrail has written versioned objects.
