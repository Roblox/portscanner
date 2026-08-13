#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH= cd -- "${AWS_DIR}/../.." && pwd -P)"
DEPLOYMENT_ROOT="${AWS_DIR}/deployment"
STATE_BOOTSTRAP_ROOT="${AWS_DIR}/state-bootstrap"

usage() {
  echo "usage: $0" >&2
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

confirm_apply() {
  local phrase="$1"
  if [[ "${PORTSCANNER_AUTO_APPROVE:-false}" == "true" ]]; then
    return 0
  fi
  printf 'Type %s to apply this saved plan: ' "${phrase}" >&2
  read -r confirmation
  [[ "${confirmation}" == "${phrase}" ]] ||
    die "stage not confirmed; saved plan discarded"
}

verify_mode_0600() {
  python3 - "$1" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
    raise SystemExit(f"{path} must be a mode-0600 regular file")
PY
}

[[ $# -eq 0 ]] || usage

for command_name in terraform aws docker jq python3 git tar; do
  require_command "${command_name}"
done
docker buildx version >/dev/null 2>&1 || die "Docker buildx is required"
TRIVY_NAME="${TRIVY:-trivy}"
require_command "${TRIVY_NAME}"

if ! TERRAFORM_VERSION_JSON="$(terraform version -json)"; then
  die "Terraform version could not be determined"
fi
if ! jq -e '.terraform_version == "1.7.4"' <<<"${TERRAFORM_VERSION_JSON}" >/dev/null; then
  die "Terraform 1.7.4 is required"
fi

if ! RESOLVED_REPOSITORY_ROOT="$(git -C "${REPOSITORY_ROOT}" rev-parse --show-toplevel 2>/dev/null)"; then
  die "repository root could not be resolved"
fi
RESOLVED_REPOSITORY_ROOT="$(CDPATH= cd -- "${RESOLVED_REPOSITORY_ROOT}" && pwd -P)"
[[ "${RESOLVED_REPOSITORY_ROOT}" == "${REPOSITORY_ROOT}" ]] ||
  die "bootstrap must run from the expected repository checkout"
if ! SOURCE_COMMIT="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)"; then
  die "the checkout has no resolvable HEAD commit"
fi
[[ "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40,64}$ ]] ||
  die "HEAD is not a supported Git object ID"
[[ -z "$(git -C "${REPOSITORY_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] ||
  die "source checkout is not clean; review and commit it before bootstrapping or publishing images"

for cli_args_name in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply; do
  cli_args_value="${!cli_args_name-}"
  for forbidden_arg in -target -destroy -refresh-only -replace; do
    if [[ "${cli_args_value}" == *"${forbidden_arg}"* ]]; then
      die "${cli_args_name} must not inject ${forbidden_arg} into bootstrap"
    fi
  done
done

CONFIG_FILE="${PORTSCANNER_CONFIG_FILE:-${DEPLOYMENT_ROOT}/environment.auto.tfvars.json}"
if [[ "${CONFIG_FILE}" != /* ]]; then
  CONFIG_FILE="$(pwd -P)/${CONFIG_FILE}"
fi
[[ -f "${CONFIG_FILE}" ]] || die "environment configuration not found: ${CONFIG_FILE}"
[[ ! -L "${CONFIG_FILE}" ]] || die "environment configuration must not be a symbolic link"

if ! CONFIG_SUMMARY="$(python3 - "${CONFIG_FILE}" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
try:
    document = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid environment JSON: {exc}") from exc

def exact_object(value, expected, label):
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    actual = set(value)
    expected_set = set(expected)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise SystemExit(f"{label} keys are invalid (missing={missing}, extra={extra})")

def integer(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise SystemExit(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise SystemExit(f"{label} must be between {minimum} and {maximum}")

def boolean(value, label):
    if not isinstance(value, bool):
        raise SystemExit(f"{label} must be true or false")

def string(value, label):
    if not isinstance(value, str):
        raise SystemExit(f"{label} must be a string")

def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{label} must be an array of strings")

def ipv4_network(value, label, exact_prefix=None):
    string(value, label)
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise SystemExit(f"{label} must be a canonical IP network: {exc}") from exc
    if network.version != 4:
        raise SystemExit(f"{label} must be IPv4")
    if exact_prefix is not None and network.prefixlen != exact_prefix:
        raise SystemExit(f"{label} must use /{exact_prefix}")
    return network

exact_object(document, ["environment"], "configuration")
environment = document["environment"]
exact_object(
    environment,
    [
        "aws",
        "integrations",
        "managed_canary",
        "name",
        "network",
        "retention",
        "runner",
        "scanner",
    ],
    "environment",
)

name = environment["name"]
string(name, "environment.name")
if re.fullmatch(r"[a-z][a-z0-9-]{1,19}", name) is None:
    raise SystemExit("environment.name must be 2-20 lowercase alphanumeric or hyphen characters")

aws = environment["aws"]
exact_object(aws, ["account_id", "region"], "environment.aws")
account_id = aws["account_id"]
region = aws["region"]
string(account_id, "environment.aws.account_id")
string(region, "environment.aws.region")
if re.fullmatch(r"[0-9]{12}", account_id) is None:
    raise SystemExit("environment.aws.account_id must be a 12-digit AWS account ID")
if re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", region) is None:
    raise SystemExit("environment.aws.region must be an AWS Region name")

network = environment["network"]
exact_object(
    network,
    ["availability_zones", "az_count", "nat_gateway_mode", "vpc_cidr"],
    "environment.network",
)
vpc = ipv4_network(network["vpc_cidr"], "environment.network.vpc_cidr")
if not 16 <= vpc.prefixlen <= 24:
    raise SystemExit("environment.network.vpc_cidr must use /16 through /24")
string_list(network["availability_zones"], "environment.network.availability_zones")
integer(network["az_count"], "environment.network.az_count", 2, 3)
if network["nat_gateway_mode"] not in {"single", "one_per_az"}:
    raise SystemExit("environment.network.nat_gateway_mode must be single or one_per_az")

runner = environment["runner"]
exact_object(
    runner,
    ["eks_installer_principal_arn", "restricted_public_cidr"],
    "environment.runner",
)
principal = runner["eks_installer_principal_arn"]
string(principal, "environment.runner.eks_installer_principal_arn")
if re.fullmatch(
    rf"arn:[^:]+:iam::{re.escape(account_id)}:(?:role|user)/.+",
    principal,
) is None:
    raise SystemExit("EKS installer principal must be a same-account IAM role or user ARN")
runner_network = ipv4_network(
    runner["restricted_public_cidr"],
    "environment.runner.restricted_public_cidr",
    32,
)
if runner_network == ipaddress.ip_network("0.0.0.0/32"):
    raise SystemExit("environment.runner.restricted_public_cidr must not be 0.0.0.0/32")

retention = environment["retention"]
exact_object(
    retention,
    [
        "bucket_expiration_days",
        "database_backup_days",
        "destroy_data_on_teardown",
        "disposable",
        "ecr_untagged_image_days",
        "lambda_log_days",
    ],
    "environment.retention",
)
boolean(retention["disposable"], "environment.retention.disposable")
boolean(
    retention["destroy_data_on_teardown"],
    "environment.retention.destroy_data_on_teardown",
)
if retention["destroy_data_on_teardown"] and not retention["disposable"]:
    raise SystemExit("destroy_data_on_teardown requires disposable=true")
integer(retention["database_backup_days"], "environment.retention.database_backup_days", 1, 35)
integer(retention["lambda_log_days"], "environment.retention.lambda_log_days", 1, 3653)
integer(
    retention["ecr_untagged_image_days"],
    "environment.retention.ecr_untagged_image_days",
    1,
    36500,
)
bucket_days = retention["bucket_expiration_days"]
exact_object(
    bucket_days,
    ["cloudtrail", "events", "findings", "results"],
    "environment.retention.bucket_expiration_days",
)
for bucket_name, days in bucket_days.items():
    integer(days, f"environment.retention.bucket_expiration_days.{bucket_name}", 1, 36500)

scanner = environment["scanner"]
exact_object(
    scanner,
    [
        "architecture",
        "max_concurrent_pods",
        "max_jobs",
        "max_rate",
        "min_rate",
        "node_instance_type",
        "operator_max_concurrent_reconciles",
    ],
    "environment.scanner",
)
integer(
    scanner["operator_max_concurrent_reconciles"],
    "environment.scanner.operator_max_concurrent_reconciles",
    1,
    32,
)
integer(scanner["max_concurrent_pods"], "environment.scanner.max_concurrent_pods", 1, 100)
integer(scanner["max_jobs"], "environment.scanner.max_jobs", 1, 1000)
integer(scanner["min_rate"], "environment.scanner.min_rate", 1, 2000)
integer(scanner["max_rate"], "environment.scanner.max_rate", 1, 5000)
if scanner["min_rate"] > scanner["max_rate"]:
    raise SystemExit("environment.scanner.min_rate must not exceed max_rate")
architecture = scanner["architecture"]
node_instance_type = scanner["node_instance_type"]
string(architecture, "environment.scanner.architecture")
string(node_instance_type, "environment.scanner.node_instance_type")
if architecture == "arm64":
    expected_node_prefix = "t4g."
    node_ami_type = "AL2023_ARM_64_STANDARD"
elif architecture == "x86_64":
    expected_node_prefix = "t3."
    node_ami_type = "AL2023_x86_64_STANDARD"
else:
    raise SystemExit("environment.scanner.architecture must be arm64 or x86_64")
if not node_instance_type.startswith(expected_node_prefix):
    raise SystemExit("node_instance_type does not match the selected architecture")

managed_canary = environment["managed_canary"]
exact_object(
    managed_canary,
    [
        "enabled",
        "expected_finding_severity",
        "instance_type",
        "listen_port",
        "vpc_cidr",
    ],
    "environment.managed_canary",
)
boolean(managed_canary["enabled"], "environment.managed_canary.enabled")
ipv4_network(
    managed_canary["vpc_cidr"],
    "environment.managed_canary.vpc_cidr",
    28,
)
string(managed_canary["instance_type"], "environment.managed_canary.instance_type")
if not managed_canary["instance_type"].startswith("t4g."):
    raise SystemExit("managed_canary.instance_type must be an ARM t4g instance")
integer(managed_canary["listen_port"], "environment.managed_canary.listen_port", 18080, 18080)
if managed_canary["expected_finding_severity"] != "low":
    raise SystemExit("managed_canary.expected_finding_severity must be low")

integrations = environment["integrations"]
exact_object(
    integrations,
    [
        "allowed_target_cidrs",
        "allowed_eni_interface_types",
        "authorized_account_ids",
        "cloudtrail_mode",
        "config_mode",
        "denied_target_cidrs",
        "existing_cloudtrail_arn",
        "existing_config_aggregator_name",
        "finding_export_enabled",
        "recurring_inventory_enabled",
        "required_target_tag_key",
        "required_target_tag_value",
        "signal_hints_enabled",
        "snapshot_regions",
    ],
    "environment.integrations",
)
for key in (
    "finding_export_enabled",
    "recurring_inventory_enabled",
    "signal_hints_enabled",
):
    boolean(integrations[key], f"environment.integrations.{key}")
for key in ("config_mode", "cloudtrail_mode"):
    if integrations[key] not in {"create", "existing", "disabled"}:
        raise SystemExit(f"environment.integrations.{key} is invalid")
for key in ("existing_config_aggregator_name", "existing_cloudtrail_arn"):
    string(integrations[key], f"environment.integrations.{key}")
if integrations["config_mode"] == "existing" and not integrations["existing_config_aggregator_name"]:
    raise SystemExit("existing config mode requires existing_config_aggregator_name")
if integrations["cloudtrail_mode"] == "existing" and not integrations["existing_cloudtrail_arn"]:
    raise SystemExit("existing cloudtrail mode requires existing_cloudtrail_arn")
string_list(integrations["snapshot_regions"], "environment.integrations.snapshot_regions")
for snapshot_region in integrations["snapshot_regions"]:
    if re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", snapshot_region) is None:
        raise SystemExit("environment.integrations.snapshot_regions contains an invalid Region")
for key in ("authorized_account_ids", "allowed_target_cidrs", "denied_target_cidrs"):
    string_list(integrations[key], f"environment.integrations.{key}")
string_list(
    integrations["allowed_eni_interface_types"],
    "environment.integrations.allowed_eni_interface_types",
)
if not integrations["allowed_eni_interface_types"] or not all(
    re.fullmatch(r"[a-z0-9-]+", value)
    for value in integrations["allowed_eni_interface_types"]
):
    raise SystemExit("allowed_eni_interface_types must contain supported lowercase names")
for key in ("required_target_tag_key", "required_target_tag_value"):
    string(integrations[key], f"environment.integrations.{key}")
if integrations["required_target_tag_key"] not in {
    "application",
    "environment",
    "name",
    "service",
}:
    raise SystemExit("required_target_tag_key is outside the shared AWS contract")
if not integrations["required_target_tag_value"]:
    raise SystemExit("required_target_tag_value must not be empty")
for authorized_account in integrations["authorized_account_ids"]:
    if re.fullmatch(r"[0-9]{12}", authorized_account) is None:
        raise SystemExit("authorized_account_ids contains an invalid AWS account ID")
for key in ("allowed_target_cidrs", "denied_target_cidrs"):
    for cidr in integrations[key]:
        ipv4_network(cidr, f"environment.integrations.{key}")

print(
    json.dumps(
        {
            "account_id": account_id,
            "architecture": architecture,
            "destroy_data_on_teardown": retention["destroy_data_on_teardown"],
            "disposable": retention["disposable"],
            "environment_name": name,
            "node_ami_type": node_ami_type,
            "node_instance_type": node_instance_type,
            "region": region,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
PY
)"; then
  die "environment configuration validation failed"
fi

ENVIRONMENT_NAME="$(jq -er '.environment_name' <<<"${CONFIG_SUMMARY}")"
EXPECTED_ACCOUNT_ID="$(jq -er '.account_id' <<<"${CONFIG_SUMMARY}")"
EXPECTED_REGION="$(jq -er '.region' <<<"${CONFIG_SUMMARY}")"
ARCHITECTURE="$(jq -er '.architecture' <<<"${CONFIG_SUMMARY}")"
EXPECTED_NODE_AMI_TYPE="$(jq -er '.node_ami_type' <<<"${CONFIG_SUMMARY}")"
EXPECTED_NODE_INSTANCE_TYPE="$(jq -er '.node_instance_type' <<<"${CONFIG_SUMMARY}")"

for region_variable in AWS_REGION AWS_DEFAULT_REGION; do
  configured_region="${!region_variable-}"
  if [[ -n "${configured_region}" && "${configured_region}" != "${EXPECTED_REGION}" ]]; then
    die "${region_variable} mismatch: configuration requires ${EXPECTED_REGION}, got ${configured_region}"
  fi
done

if ! AWS_IDENTITY_JSON="$(
  aws sts get-caller-identity \
    --region "${EXPECTED_REGION}" \
    --output json
)"; then
  die "AWS identity is unavailable in configured Region ${EXPECTED_REGION}"
fi
ACTUAL_ACCOUNT_ID="$(jq -er '.Account | select(test("^[0-9]{12}$"))' <<<"${AWS_IDENTITY_JSON}")" ||
  die "AWS identity response has no valid account ID"
AWS_IDENTITY_ARN="$(jq -er '.Arn | select(type == "string" and length > 0)' <<<"${AWS_IDENTITY_JSON}")" ||
  die "AWS identity response has no ARN"
[[ "${ACTUAL_ACCOUNT_ID}" == "${EXPECTED_ACCOUNT_ID}" ]] ||
  die "AWS identity mismatch: expected account ${EXPECTED_ACCOUNT_ID}, got ${ACTUAL_ACCOUNT_ID}"

export AWS_REGION="${EXPECTED_REGION}"
export AWS_DEFAULT_REGION="${EXPECTED_REGION}"
export PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_ACCOUNT_ID}"
export PORTSCANNER_EXPECTED_AWS_REGION="${EXPECTED_REGION}"
export PORTSCANNER_CONFIG_FILE="${CONFIG_FILE}"

ARTIFACT_ROOT="${PORTSCANNER_ARTIFACT_ROOT:-${REPOSITORY_ROOT}/.portscanner}"
if [[ "${ARTIFACT_ROOT}" != /* ]]; then
  ARTIFACT_ROOT="$(pwd -P)/${ARTIFACT_ROOT}"
fi
[[ ! -L "${ARTIFACT_ROOT}" ]] || die "artifact root must not be a symbolic link"
ARTIFACT_DIR="${ARTIFACT_ROOT}/${ENVIRONMENT_NAME}/${EXPECTED_ACCOUNT_ID}/${EXPECTED_REGION}"
BACKEND_KEY="environments/${ENVIRONMENT_NAME}/${EXPECTED_ACCOUNT_ID}/${EXPECTED_REGION}/deployment.tfstate"
if [[ ! "${BACKEND_KEY}" =~ ^environments/[a-z][a-z0-9-]{1,19}/[0-9]{12}/[a-z]{2}(-[a-z0-9]+)+-[0-9]+/deployment\.tfstate$ ]] ||
  [[ "${BACKEND_KEY}" == /* || "${BACKEND_KEY}" == *".."* || "${BACKEND_KEY}" == *"//"* ]]; then
  die "derived backend key is unsafe: ${BACKEND_KEY}"
fi

umask 077
mkdir -p "${ARTIFACT_DIR}"
[[ ! -L "${ARTIFACT_DIR}" ]] || die "artifact directory must not be a symbolic link"

BOOTSTRAP_STATE="${ARTIFACT_DIR}/state-bootstrap.tfstate"
BOOTSTRAP_BACKUP="${BOOTSTRAP_STATE}.backup"
BACKEND_CONFIG="${ARTIFACT_DIR}/backend.hcl"
IMAGE_INPUTS="${ARTIFACT_DIR}/images.tfvars"
STATE_DATA_DIR="${ARTIFACT_DIR}/state-bootstrap-data"
STATE_PREFIX="${ENVIRONMENT_NAME}-state"
EXPECTED_LOCK_TABLE="${STATE_PREFIX}-terraform-locks"
EXPECTED_BUCKET_PREFIX="${STATE_PREFIX}-tfstate-"

if [[ ! -f "${BOOTSTRAP_STATE}" && -e "${BACKEND_CONFIG}" ]]; then
  die "backend configuration exists without its bootstrap state; refusing a possible collision"
fi
if [[ ! -f "${BOOTSTRAP_STATE}" && -e "${BOOTSTRAP_BACKUP}" ]]; then
  die "bootstrap state backup exists without primary state; restore or review it before continuing"
fi
if [[ ! -f "${BOOTSTRAP_STATE}" ]]; then
  if ! EXISTING_LOCK_TABLES="$(
    aws dynamodb list-tables \
      --region "${EXPECTED_REGION}" \
      --query TableNames \
      --output json
  )"; then
    die "could not check for an existing state lock table"
  fi
  if ! jq -e 'type == "array" and all(.[]; type == "string")' \
    <<<"${EXISTING_LOCK_TABLES}" >/dev/null; then
    die "DynamoDB returned a malformed state lock-table inventory"
  fi
  if jq -e --arg table "${EXPECTED_LOCK_TABLE}" 'index($table) != null' \
    <<<"${EXISTING_LOCK_TABLES}" >/dev/null; then
    die "bootstrap state collision: lock table ${EXPECTED_LOCK_TABLE} already exists without matching local bootstrap state"
  fi
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-bootstrap.XXXXXX")"
BACKEND_CANDIDATE=""
IMAGE_CANDIDATE=""
cleanup() {
  [[ -z "${BACKEND_CANDIDATE}" ]] || rm -f -- "${BACKEND_CANDIDATE}"
  [[ -z "${IMAGE_CANDIDATE}" ]] || rm -f -- "${IMAGE_CANDIDATE}"
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

mkdir -p "${STATE_DATA_DIR}"
TF_DATA_DIR="${STATE_DATA_DIR}" terraform "-chdir=${STATE_BOOTSTRAP_ROOT}" init \
  -backend=false \
  -input=false

read_bootstrap_configuration() {
  TF_DATA_DIR="${STATE_DATA_DIR}" terraform "-chdir=${STATE_BOOTSTRAP_ROOT}" output \
    -state="${BOOTSTRAP_STATE}" \
    -json backend_configuration
}

validate_bootstrap_configuration() {
  local configuration_json="$1"
  local bucket
  local region
  local lock_table
  local table_arn

  if ! jq -e '
    type == "object" and
    keys == ["bucket", "dynamodb_table", "encrypt", "region"] and
    (.bucket | type == "string") and
    (.dynamodb_table | type == "string") and
    (.region | type == "string") and
    .encrypt == true
  ' <<<"${configuration_json}" >/dev/null; then
    die "state-bootstrap output is malformed"
  fi
  bucket="$(jq -er '.bucket | select(test("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"))' <<<"${configuration_json}")" ||
    die "state-bootstrap bucket output is unsafe"
  region="$(jq -er '.region' <<<"${configuration_json}")"
  lock_table="$(jq -er '.dynamodb_table | select(test("^[A-Za-z0-9_.-]{3,255}$"))' <<<"${configuration_json}")" ||
    die "state-bootstrap lock-table output is unsafe"
  [[ "${bucket}" == "${EXPECTED_BUCKET_PREFIX}"* ]] ||
    die "bootstrap state collision: bucket ${bucket} does not match ${EXPECTED_BUCKET_PREFIX}*"
  [[ "${region}" == "${EXPECTED_REGION}" ]] ||
    die "bootstrap state collision: expected Region ${EXPECTED_REGION}, got ${region}"
  [[ "${lock_table}" == "${EXPECTED_LOCK_TABLE}" ]] ||
    die "bootstrap state collision: expected lock table ${EXPECTED_LOCK_TABLE}, got ${lock_table}"

  aws s3api head-bucket \
    --bucket "${bucket}" \
    --expected-bucket-owner "${EXPECTED_ACCOUNT_ID}" \
    --region "${EXPECTED_REGION}" >/dev/null ||
    die "state bucket is unavailable or is not owned by the configured account"
  table_arn="$(
    aws dynamodb describe-table \
      --table-name "${lock_table}" \
      --region "${EXPECTED_REGION}" \
      --query Table.TableArn \
      --output text
  )" || die "state lock table is unavailable"
  [[ "${table_arn}" =~ ^arn:[^:]+:dynamodb:${EXPECTED_REGION}:${EXPECTED_ACCOUNT_ID}:table/${EXPECTED_LOCK_TABLE}$ ]] ||
    die "state lock table identity does not match the configured account and Region"
}

if [[ -f "${BOOTSTRAP_STATE}" ]]; then
  EXISTING_BACKEND_JSON="$(read_bootstrap_configuration)" ||
    die "existing bootstrap state is unreadable; refusing to overwrite it"
  validate_bootstrap_configuration "${EXISTING_BACKEND_JSON}"
  log "verified resumable state bootstrap for ${ENVIRONMENT_NAME}"
fi

BOOTSTRAP_PLAN="${WORK_DIR}/state-bootstrap.tfplan"
TF_DATA_DIR="${STATE_DATA_DIR}" terraform "-chdir=${STATE_BOOTSTRAP_ROOT}" plan \
  -input=false \
  -state="${BOOTSTRAP_STATE}" \
  -out="${BOOTSTRAP_PLAN}" \
  "-var=aws_region=${EXPECTED_REGION}" \
  "-var=expected_deployment_account_id=${EXPECTED_ACCOUNT_ID}" \
  "-var=name_prefix=${STATE_PREFIX}"
TF_DATA_DIR="${STATE_DATA_DIR}" terraform "-chdir=${STATE_BOOTSTRAP_ROOT}" show "${BOOTSTRAP_PLAN}"
confirm_apply "state-bootstrap"
TF_DATA_DIR="${STATE_DATA_DIR}" terraform "-chdir=${STATE_BOOTSTRAP_ROOT}" apply \
  -input=false \
  -state="${BOOTSTRAP_STATE}" \
  -backup="${BOOTSTRAP_BACKUP}" \
  "${BOOTSTRAP_PLAN}"
chmod 600 "${BOOTSTRAP_STATE}"
[[ ! -f "${BOOTSTRAP_BACKUP}" ]] || chmod 600 "${BOOTSTRAP_BACKUP}"
verify_mode_0600 "${BOOTSTRAP_STATE}"

BACKEND_JSON="$(read_bootstrap_configuration)" ||
  die "state-bootstrap did not produce backend_configuration"
validate_bootstrap_configuration "${BACKEND_JSON}"
STATE_BUCKET="$(jq -er .bucket <<<"${BACKEND_JSON}")"
LOCK_TABLE="$(jq -er .dynamodb_table <<<"${BACKEND_JSON}")"

BACKEND_CANDIDATE="$(mktemp "${ARTIFACT_DIR}/.backend.hcl.XXXXXX")"
cat >"${BACKEND_CANDIDATE}" <<EOF
bucket         = "${STATE_BUCKET}"
key            = "${BACKEND_KEY}"
region         = "${EXPECTED_REGION}"
dynamodb_table = "${LOCK_TABLE}"
encrypt        = true
EOF
chmod 600 "${BACKEND_CANDIDATE}"
if [[ -e "${BACKEND_CONFIG}" ]]; then
  [[ -f "${BACKEND_CONFIG}" && ! -L "${BACKEND_CONFIG}" ]] ||
    die "backend configuration must be a regular file"
  cmp -s "${BACKEND_CANDIDATE}" "${BACKEND_CONFIG}" ||
    die "backend configuration collision: existing file does not match derived state identity"
  chmod 600 "${BACKEND_CONFIG}"
else
  mv "${BACKEND_CANDIDATE}" "${BACKEND_CONFIG}"
fi
verify_mode_0600 "${BACKEND_CONFIG}"

export PORTSCANNER_ARTIFACT_ROOT="${ARTIFACT_ROOT}"
export TF_BACKEND_CONFIG="${BACKEND_CONFIG}"
export PORTSCANNER_IMAGE_VARS_FILE="${IMAGE_INPUTS}"

terraform "-chdir=${DEPLOYMENT_ROOT}" init \
  -input=false \
  -reconfigure \
  "-backend-config=${BACKEND_CONFIG}"

DEPLOY_SCRIPT="${PORTSCANNER_DEPLOY_SCRIPT:-${SCRIPT_DIR}/deploy.sh}"
[[ -x "${DEPLOY_SCRIPT}" ]] || die "deployment helper is not executable: ${DEPLOY_SCRIPT}"
CURRENT_STATE=""
if CURRENT_STATE="$(terraform "-chdir=${DEPLOYMENT_ROOT}" output -json deployment_state 2>/dev/null)"; then
  if ! jq -e '
    type == "object" and
    keys == [
      "automatic_inventory_enabled",
      "canary_mode",
      "dispatch_enabled",
      "finding_export_enabled",
      "managed_canary_enabled",
      "migration_run",
      "operator_installed",
      "periodic_coverage_enabled",
      "periodic_snapshots_enabled",
      "processor_reconciliation_enabled",
      "runtime_created",
      "signal_hints_enabled"
    ] and
    all(.[]; type == "boolean")
  ' <<<"${CURRENT_STATE}" >/dev/null; then
    die "canonical deployment_state output is malformed"
  fi
fi
if [[ -n "${CURRENT_STATE}" ]] && jq -e '
  .runtime_created or .migration_run or .operator_installed or
  .dispatch_enabled or .automatic_inventory_enabled or .canary_mode or
  .periodic_snapshots_enabled or .periodic_coverage_enabled or
  .signal_hints_enabled or .processor_reconciliation_enabled
' <<<"${CURRENT_STATE}" >/dev/null; then
  log "canonical foundation already exists at a later stage; no rollback attempted"
else
  "${DEPLOY_SCRIPT}" foundation
fi

BUILD_IMAGES_SCRIPT="${PORTSCANNER_BUILD_IMAGES_SCRIPT:-${SCRIPT_DIR}/build-images.sh}"
[[ -x "${BUILD_IMAGES_SCRIPT}" ]] || die "image build helper is not executable: ${BUILD_IMAGES_SCRIPT}"
IMAGE_CANDIDATE="$(mktemp "${ARTIFACT_DIR}/.images.tfvars.XXXXXX")"
"${BUILD_IMAGES_SCRIPT}" "${DEPLOYMENT_ROOT}" "${ARCHITECTURE}" >"${IMAGE_CANDIDATE}"

python3 - \
  "${IMAGE_CANDIDATE}" \
  "${ARCHITECTURE}" \
  "${EXPECTED_NODE_AMI_TYPE}" \
  "${EXPECTED_NODE_INSTANCE_TYPE}" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
expected_architecture = sys.argv[2]
expected_node_ami = sys.argv[3]
expected_node_type = sys.argv[4]
text = path.read_text(encoding="utf-8")
match = re.fullmatch(
    r'image_digests = \{\n(?P<digests>(?:  [a-z]+ +='
    r' "sha256:[0-9a-f]{64}"\n)+)\}\n\n'
    r'migration_checksum = "(?P<migration>[0-9a-f]{64})"\n'
    r'lambda_architecture = "(?P<architecture>arm64|x86_64)"\n'
    r'node_ami_type = "(?P<ami>[A-Za-z0-9_]+)"\n'
    r'node_instance_types = (?P<nodes>\[[^\n]+\])\n',
    text,
)
if match is None:
    raise SystemExit("generated image input has an unexpected shape")
components = re.findall(r"^  ([a-z]+) +=", match.group("digests"), re.MULTILINE)
if components != [
    "inventory",
    "generator",
    "parser",
    "processor",
    "migrator",
    "operator",
    "scanner",
]:
    raise SystemExit("generated image input does not contain the seven ordered components")
try:
    nodes = json.loads(match.group("nodes"))
except json.JSONDecodeError as exc:
    raise SystemExit("generated node_instance_types is invalid JSON") from exc
if match.group("architecture") != expected_architecture:
    raise SystemExit("generated image architecture does not match environment configuration")
if match.group("ami") != expected_node_ami:
    raise SystemExit("generated node AMI does not match environment configuration")
if nodes != [expected_node_type]:
    raise SystemExit("generated node types do not match environment configuration")
PY

chmod 600 "${IMAGE_CANDIDATE}"
mv "${IMAGE_CANDIDATE}" "${IMAGE_INPUTS}"
verify_mode_0600 "${IMAGE_INPUTS}"

log "Bootstrap complete for ${ENVIRONMENT_NAME} using ${AWS_IDENTITY_ARN} in ${EXPECTED_REGION}."
log "Backend and generated image inputs are private artifacts under ${ARTIFACT_DIR}."
log "Run ${SCRIPT_DIR}/deploy.sh ready to create the paused runtime."
