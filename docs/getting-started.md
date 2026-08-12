<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Getting started

This path proves the repository locally, deploys one paused AWS evaluation, verifies one
explicitly authorized canary, and then pauses scanning before any broader integration.

The AWS evaluation is not free or one-click. Its foundation creates a VPC, NAT gateway,
EKS control plane and node, Aurora PostgreSQL, queues, buckets, tables, repositories,
logs, and alarms. Use a dedicated sandbox account, review current AWS
pricing and quotas, and destroy the evaluation promptly. Never point it at an address
you do not own or have written authorization to test.

## 1. Prove the checkout locally

Required for the full local path:

- Python 3.12 and [`uv`](https://docs.astral.sh/uv/);
- Go from `operator/go.mod`;
- Terraform 1.7.4;
- `kubectl` with Kustomize support, Helm 3, and kubeconform 0.8; and
- Docker for the isolated PostgreSQL integration tests.

Run:

```bash
git clone https://github.com/Roblox/portscanner.git
cd portscanner

make sync
make check
make test-go
make test-go-envtest
make vet-go
make test-postgresql
make terraform-script-tests
make terraform-validate
make kubernetes-validate
```

These checks use synthetic data and do not scan a network target. The PostgreSQL target
starts a digest-pinned local PostgreSQL 16 container, applies every migration, exercises
the parser/database path, and removes the container.

## 2. Prepare one AWS evaluation

You need:

- a dedicated AWS account or an approved sandbox boundary;
- a short-lived deployment identity with permission to create the documented resources;
- one stable IAM role or user ARN for EKS installation (not an STS session ARN);
- one public IPv4 address of the Terraform runner for restricted EKS API access;
- one public IPv4 canary attached to an in-use EC2 network interface in the authorized
  account and Region; and
- written authorization for the account, canary `/32`, scan window, and source egress.

The image publication step additionally requires Git, the AWS CLI, Docker buildx, `jq`,
Python 3, `tar`, and Trivy.

Copy the guarded evaluation values:

```bash
export TF_ROOT="$PWD/terraform/aws/examples/created-vpc"
export TF_VARS="$TF_ROOT/evaluation.tfvars"

cp "$TF_ROOT/evaluation.tfvars.example" "$TF_VARS"
chmod 600 "$TF_VARS"
```

Replace every `REPLACE_*` value. Confirm the account before continuing:

```bash
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="$(
  aws sts get-caller-identity \
    --region "$AWS_REGION" \
    --query Account \
    --output text
)"
export PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID="$AWS_ACCOUNT_ID"
export PORTSCANNER_EXPECTED_AWS_REGION="$AWS_REGION"

test "$AWS_ACCOUNT_ID" != "123456789012"
aws sts get-caller-identity --region "$AWS_REGION"
terraform version
```

The staged helper refuses to plan if the live account differs from
`PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID`, and it forces that account plus
`PORTSCANNER_EXPECTED_AWS_REGION` into the reviewed Terraform plan. Keep the same values
in `evaluation.tfvars`.

The example deliberately:

- uses direct EC2 snapshots instead of creating the account's singleton AWS Config
  recorder;
- disables CloudTrail and local API-call hints for the one-shot test;
- limits scanning to one authorized account and one public `/32`;
- enables the EKS public endpoint only for the runner's restricted IPv4 CIDR while
  retaining private endpoint access; and
- permits bucket and ECR cleanup because it is intended only for disposable evaluation
  data and images.

`0.0.0.0/0` is rejected for EKS API access. For production, disable the public endpoint
and supply approved private runner or VPN security groups instead.

Production can set `cloudtrail_mode = "create"` for a project-owned multi-Region
management trail or `"existing"` with an approved `existing_cloudtrail_arn`. Do not
enable API-call hints until that account-level choice has been reviewed.

## 3. Bootstrap remote state

Create the state bucket and lock table once. Keep the bootstrap's local state secure:

```bash
terraform -chdir=terraform/aws/state-bootstrap init
terraform -chdir=terraform/aws/state-bootstrap apply \
  -var="aws_region=$AWS_REGION" \
  -var="expected_deployment_account_id=$AWS_ACCOUNT_ID" \
  -var='name_prefix=portscanner-eval'
```

Write the non-secret backend settings outside the repository and add a unique state key:

```bash
export TF_BACKEND_CONFIG="$HOME/portscanner-eval-backend.hcl"

terraform -chdir=terraform/aws/state-bootstrap \
  output -json backend_configuration |
  jq -r 'to_entries[] | "\(.key) = \(.value | tojson)"' \
  >"$TF_BACKEND_CONFIG"
printf '%s\n' 'key = "environments/portscanner-eval.tfstate"' \
  >>"$TF_BACKEND_CONFIG"
chmod 600 "$TF_BACKEND_CONFIG"
```

Do not put credentials in the backend file or reuse its key for another root.

## 4. Apply the paused foundation

The deployment helper saves a plan, forces all runtime/dispatch switches off, and asks
you to type the stage name before applying:

```bash
terraform/aws/scripts/deploy.sh \
  "$TF_ROOT" foundation "$TF_VARS"
```

Read the plan. Reject unexpected changes to shared Config, CloudTrail, networking,
databases, clusters, or policies. AWS charges begin at this stage, but no scanner work
is dispatched.

Confirm the gate:

```bash
terraform -chdir="$TF_ROOT" output -json deployment_state
```

Every value must be `false`.

## 5. Publish immutable images

First validate the image map without logging in, building, or pushing:

```bash
terraform/aws/scripts/build-images.sh --dry-run "$TF_ROOT" arm64
```

Then build the reviewed clean commit, scan every image, push immutable tags, and retain
the resulting digests in a private file:

```bash
export IMAGE_VARS="$HOME/portscanner-eval-images.tfvars"
export SOURCE_REVISION="$(git rev-parse HEAD)"

(umask 077
 terraform/aws/scripts/build-images.sh \
   "$TF_ROOT" arm64 "$SOURCE_REVISION" >"$IMAGE_VARS")
```

The default Terraform architecture is ARM64. For x86, set the foundation to
`lambda_architecture = "x86_64"`, `node_ami_type = "AL2023_x86_64_STANDARD"`, and an
x86-compatible `node_instance_types` value such as `["t3.medium"]`, then invoke the
builder with `x86_64`. The helper rejects a mismatch with the applied foundation and
emits those matching runtime values with the image digests.

## 6. Install the paused runtime

The helper accepts both the environment values and the generated image values:

```bash
terraform/aws/scripts/deploy.sh \
  "$TF_ROOT" runtime "$TF_VARS" "$IMAGE_VARS"

terraform/aws/scripts/deploy.sh \
  "$TF_ROOT" migrate "$TF_VARS" "$IMAGE_VARS"
```

The runtime stage creates digest-pinned functions with schedules and queue mappings
paused. The migrate stage applies checksum-locked migrations, creates the application
database credential, and installs the operator. Dispatch remains off.

Verify that the runner can reach the EKS endpoint, the node is ready, the operator is
healthy, and every deployed image uses the recorded digest. If the runner's public
address changes, update `eks_public_access_cidrs` before retrying.

## 7. Verify exactly one canary

Before activation:

1. Confirm `allowed_target_cidrs` still contains only the authorized canary `/32`.
2. Confirm the canary's EC2 network interface is in the authorized account and Region,
   is in use, and still owns that public address.
3. Read the scanner egress address:

   ```bash
   terraform -chdir="$TF_ROOT" output -json scanner_egress_public_ips
   ```

4. Permit the agreed canary service port from that egress address in the canary security
   group, and run a disposable service on that port.
5. Reconfirm the test window and owner.

The first-release `new_target` path runs a bounded full TCP scan over ports 1-65535, even
when only one canary service is expected to be open. The authorization and maintenance
window must cover that exact behavior. The evaluation file limits the operator to one
concurrent reconciliation, hard-caps active scanner Pods at one and scanner Job objects
at four, and passes 100-250 probes/second to the scanner.

Enable only the priority/result queue and stream pipeline. The durable outbox-replay
repair schedule is enabled; automatic snapshot/rescan/processor schedules, EventBridge
inventory hints, signal consumption, and coverage consumption remain disabled:

```bash
terraform/aws/scripts/deploy.sh \
  "$TF_ROOT" canary "$TF_VARS" "$IMAGE_VARS"
```

Invoke one exact public IPv4 in one account and Region. This still reads the Region's EC2
inventory, but only the matching address is reconciled and no absence removals run:

```bash
export CANARY_IP="REPLACE_WITH_AUTHORIZED_PUBLIC_IPV4"
export SNAPSHOT_FUNCTION_ARN="$(
  terraform -chdir="$TF_ROOT" output -json function_arns |
    jq -r '.snapshot'
)"

aws lambda invoke \
  --region "$AWS_REGION" \
  --function-name "$SNAPSHOT_FUNCTION_ARN" \
  --cli-binary-format raw-in-base64-out \
  --payload "$(
    jq -nc \
      --arg account_id "$AWS_ACCOUNT_ID" \
      --arg region "$AWS_REGION" \
      --arg target "$CANARY_IP" \
      '{
        account_id: $account_id,
        region: $region,
        target_public_ipv4: $target
      }'
  )" \
  "${TMPDIR:-/tmp}/portscanner-canary-response.json"
jq . "${TMPDIR:-/tmp}/portscanner-canary-response.json"
```

The generator rereads current ownership immediately before dispatch, the scanner verifies
the public edge, and an observed open service produces an immutable finding handoff. Do
not omit `account_id`, `region`, or `target_public_ipv4`: canary mode rejects an
out-of-scope request and requires the address to resolve to exactly one inventory target
in a complete response before writing state.

Inspect the external finding queue and object by following
[Integrating findings](integrating-findings.md). Validate the object against
`schemas/finding.schema.json` or the shared semantic validator before accepting it.

As soon as the canary is proven, pause the mappings while schedules and signal rules
remain disabled, retaining the runtime and evidence:

```bash
terraform/aws/scripts/deploy.sh \
  "$TF_ROOT" pause-canary "$TF_VARS" "$IMAGE_VARS"
```

The pause helper applies only saved plans containing dispatch mapping/rule updates. It
rejects migration, image, Helm, and other infrastructure changes.

If the cluster API cannot be reached, disable the AWS producers and mappings without a
Terraform plan or Helm refresh:

```bash
terraform/aws/scripts/emergency-pause.sh "$TF_ROOT"
```

This does not terminate an already running scanner Job; follow the authorized
Kubernetes or AWS network/node-group stop procedure for that separate step.

Do not broaden the account, Region, or CIDR scope until queue age, ownership verdicts,
scan outcomes, finding delivery, cost, and cleanup have all been reviewed.

## 8. Integrate, expand, or remove

Keep Portscanner's immutable finding bucket and external SQS queue as the boundary to
your ticketing, SIEM, paging, or data platform. The integration should be idempotent by
`event.event_key`, tolerate duplicate S3 notifications, and delete an SQS message only
after the referenced object has been fetched and validated.

For production, create a separate reviewed variable set: disable public EKS API access,
use private runner/VPN security groups, disable forced bucket/repository deletion,
enable database protection and final snapshots, enable DynamoDB PITR, add resilient
NAT/nodes/database capacity, and set policy-appropriate retention and alarms.

For a disposable evaluation, pause first and retain or export any required evidence.
Then create and review a destroy plan while keeping the migrated configuration visible
to Terraform:

```bash
export DESTROY_PLAN="$HOME/portscanner-eval-destroy.tfplan"

terraform -chdir="$TF_ROOT" plan -destroy \
  -var-file="$TF_VARS" \
  -var-file="$IMAGE_VARS" \
  -var=deploy_runtime=true \
  -var=run_migration=true \
  -var=install_operator=true \
  -var=enable_event_dispatch=false \
  -var=enable_automatic_inventory=false \
  -var=canary_mode=false \
  -out="$DESTROY_PLAN"

terraform -chdir="$TF_ROOT" show "$DESTROY_PLAN"
terraform -chdir="$TF_ROOT" apply "$DESTROY_PLAN"
rm -f "$DESTROY_PLAN"
```

Confirm the application resources are gone. The state bootstrap intentionally has
`prevent_destroy` and requires a separate retirement decision. Production removal must
instead follow the retention and destruction procedure in
[AWS deployment](aws-deployment.md).
