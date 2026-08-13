#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REPOSITORY_ROOT="$(CDPATH= cd -- "${AWS_DIR}/../.." && pwd -P)"
CANONICAL_ROOT="${AWS_DIR}/deployment"

usage() {
  cat >&2 <<EOF
usage:
  $0 <foundation|runtime|migrate|canary|activate|pause|pause-canary|ready|evaluate|retire-canary|destroy>
  $0 <terraform-root> <foundation|runtime|migrate|canary|activate|pause|pause-canary> [variables.tfvars ...]
EOF
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

is_stage() {
  case "$1" in
    foundation | runtime | migrate | canary | activate | pause | pause-canary | ready | evaluate | retire-canary | destroy)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

file_mode() {
  local path="$1"
  local mode
  if mode="$(stat -f '%Lp' "${path}" 2>/dev/null)"; then
    printf '%s' "${mode}"
  else
    stat -c '%a' "${path}"
  fi
}

require_private_generated_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] ||
    die "${label} must be a regular generated file: ${path}"
  [[ "$(file_mode "${path}")" == "600" ]] ||
    die "${label} must have mode 0600: ${path}"
}

require_command terraform
require_command aws

[[ $# -ge 1 ]] || usage
CANONICAL_MODE=false
CONFIG_FILE=""
ENVIRONMENT_NAME=""
DISPOSABLE=false
DESTROY_DATA_ON_TEARDOWN=false

if is_stage "$1"; then
  [[ $# -eq 1 ]] || usage
  CANONICAL_MODE=true
  ROOT="${CANONICAL_ROOT}"
  STAGE="$1"
else
  [[ $# -ge 2 ]] || usage
  ROOT_ARG="$1"
  STAGE="$2"
  is_stage "${STAGE}" || usage
  case "${STAGE}" in
    ready | evaluate | retire-canary | destroy)
      die "${STAGE} is available only with the canonical no-root invocation"
      ;;
  esac
  if [[ "${ROOT_ARG}" = /* ]]; then
    ROOT_CANDIDATE="${ROOT_ARG}"
  else
    ROOT_CANDIDATE="$(pwd -P)/${ROOT_ARG}"
  fi
  [[ -d "${ROOT_CANDIDATE}" ]] || die "Terraform root does not exist: ${ROOT_ARG}"
  ROOT="$(CDPATH= cd -- "${ROOT_CANDIDATE}" && pwd -P)"
fi

case "${ROOT}/" in
  "${AWS_DIR}/"*) ;;
  *) die "terraform root must remain under ${AWS_DIR}" ;;
esac
[[ -f "${ROOT}/main.tf" ]] || die "${ROOT} is not a Terraform root with main.tf"

PLAN_ARGS=()
if [[ "${CANONICAL_MODE}" == "true" ]]; then
  require_command jq
  CONFIG_FILE="${PORTSCANNER_CONFIG_FILE:-${CANONICAL_ROOT}/environment.auto.tfvars.json}"
  if [[ "${CONFIG_FILE}" != /* ]]; then
    CONFIG_FILE="$(pwd -P)/${CONFIG_FILE}"
  fi
  [[ -f "${CONFIG_FILE}" && ! -L "${CONFIG_FILE}" ]] ||
    die "canonical environment configuration not found: ${CONFIG_FILE}; copy environment.auto.tfvars.json.example"

  if ! CONFIG_SUMMARY="$(jq -ce '
    . as $document
    | .environment as $environment
    | if (
        ($document | type == "object" and keys == ["environment"]) and
        ($environment | type == "object" and keys == [
          "aws",
          "integrations",
          "managed_canary",
          "name",
          "network",
          "retention",
          "runner",
          "scanner"
        ]) and
        ($environment.name | type == "string" and test("^[a-z][a-z0-9-]{1,19}$")) and
        ($environment.aws | type == "object" and keys == ["account_id", "region"]) and
        ($environment.aws.account_id | type == "string" and test("^[0-9]{12}$")) and
        ($environment.aws.region | type == "string" and test("^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$")) and
        ($environment.network | type == "object" and keys == ["availability_zones", "az_count", "nat_gateway_mode", "vpc_cidr"]) and
        ($environment.runner | type == "object" and keys == ["eks_installer_principal_arn", "restricted_public_cidr"]) and
        ($environment.runner.eks_installer_principal_arn | type == "string") and
        ($environment.runner.restricted_public_cidr | type == "string" and test("/32$") and . != "0.0.0.0/0") and
        ($environment.retention | type == "object" and keys == [
          "bucket_expiration_days",
          "database_backup_days",
          "destroy_data_on_teardown",
          "disposable",
          "ecr_untagged_image_days",
          "lambda_log_days"
        ]) and
        ($environment.retention.disposable | type == "boolean") and
        ($environment.retention.destroy_data_on_teardown | type == "boolean") and
        (($environment.retention.destroy_data_on_teardown | not) or $environment.retention.disposable) and
        ($environment.scanner | type == "object" and keys == [
          "architecture",
          "max_concurrent_pods",
          "max_jobs",
          "max_rate",
          "min_rate",
          "node_instance_type",
          "operator_max_concurrent_reconciles"
        ]) and
        ($environment.scanner.architecture == "arm64" or $environment.scanner.architecture == "x86_64") and
        ($environment.managed_canary | type == "object" and keys == [
          "enabled",
          "expected_finding_severity",
          "instance_type",
          "listen_port",
          "vpc_cidr"
        ]) and
        ($environment.managed_canary.enabled | type == "boolean") and
        ($environment.integrations | type == "object" and keys == [
          "allowed_eni_interface_types",
          "allowed_target_cidrs",
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
          "snapshot_regions"
        ])
      ) then
        {
          account_id: $environment.aws.account_id,
          architecture: $environment.scanner.architecture,
          destroy_data_on_teardown: $environment.retention.destroy_data_on_teardown,
          disposable: $environment.retention.disposable,
          environment_name: $environment.name,
          region: $environment.aws.region
        }
      else
        error("canonical environment configuration is malformed")
      end
  ' "${CONFIG_FILE}")"; then
    die "canonical environment configuration validation failed"
  fi

  ENVIRONMENT_NAME="$(jq -er .environment_name <<<"${CONFIG_SUMMARY}")"
  EXPECTED_ACCOUNT_ID="$(jq -er .account_id <<<"${CONFIG_SUMMARY}")"
  EXPECTED_REGION="$(jq -er .region <<<"${CONFIG_SUMMARY}")"
  DISPOSABLE="$(jq -er '.disposable | tostring' <<<"${CONFIG_SUMMARY}")"
  DESTROY_DATA_ON_TEARDOWN="$(jq -er '.destroy_data_on_teardown | tostring' <<<"${CONFIG_SUMMARY}")"

  if [[ -n "${PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID:-}" &&
    "${PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID}" != "${EXPECTED_ACCOUNT_ID}" ]]; then
    die "PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID conflicts with canonical environment configuration"
  fi
  if [[ -n "${PORTSCANNER_EXPECTED_AWS_REGION:-}" &&
    "${PORTSCANNER_EXPECTED_AWS_REGION}" != "${EXPECTED_REGION}" ]]; then
    die "PORTSCANNER_EXPECTED_AWS_REGION conflicts with canonical environment configuration"
  fi

  ARTIFACT_ROOT="${PORTSCANNER_ARTIFACT_ROOT:-${REPOSITORY_ROOT}/.portscanner}"
  if [[ "${ARTIFACT_ROOT}" != /* ]]; then
    ARTIFACT_ROOT="$(pwd -P)/${ARTIFACT_ROOT}"
  fi
  ARTIFACT_DIR="${ARTIFACT_ROOT}/${ENVIRONMENT_NAME}/${EXPECTED_ACCOUNT_ID}/${EXPECTED_REGION}"
  DERIVED_BACKEND_CONFIG="${ARTIFACT_DIR}/backend.hcl"
  IMAGE_INPUTS="${PORTSCANNER_IMAGE_VARS_FILE:-${ARTIFACT_DIR}/images.tfvars}"
  BACKEND_CONFIG="${TF_BACKEND_CONFIG:-${DERIVED_BACKEND_CONFIG}}"
  if [[ "${BACKEND_CONFIG}" != /* ]]; then
    BACKEND_CONFIG="$(pwd -P)/${BACKEND_CONFIG}"
  fi
  if [[ "${IMAGE_INPUTS}" != /* ]]; then
    IMAGE_INPUTS="$(pwd -P)/${IMAGE_INPUTS}"
  fi

  require_private_generated_file "${BACKEND_CONFIG}" "backend configuration"
  BACKEND_KEY="environments/${ENVIRONMENT_NAME}/${EXPECTED_ACCOUNT_ID}/${EXPECTED_REGION}/deployment.tfstate"
  [[ "${BACKEND_KEY}" != /* && "${BACKEND_KEY}" != *".."* && "${BACKEND_KEY}" != *"//"* ]] ||
    die "derived backend key is unsafe"
  BACKEND_CONTENT="$(<"${BACKEND_CONFIG}")"
  [[ "${BACKEND_CONTENT}" == *"key            = \"${BACKEND_KEY}\""* ]] ||
    die "backend configuration key does not match the canonical environment identity"
  [[ "${BACKEND_CONTENT}" == *"region         = \"${EXPECTED_REGION}\""* ]] ||
    die "backend configuration Region does not match the canonical environment identity"
  [[ "${BACKEND_CONTENT}" == *"encrypt        = true"* ]] ||
    die "backend configuration must enable encryption"
  backend_bucket_fields=0
  backend_key_fields=0
  backend_region_fields=0
  backend_lock_fields=0
  backend_encrypt_fields=0
  while IFS= read -r backend_line; do
    [[ -n "${backend_line}" && "${backend_line}" == *=* ]] ||
      die "backend configuration has an unexpected line"
    backend_field="${backend_line%%=*}"
    backend_field="${backend_field//[[:space:]]/}"
    case "${backend_field}" in
      bucket) backend_bucket_fields=$((backend_bucket_fields + 1)) ;;
      key) backend_key_fields=$((backend_key_fields + 1)) ;;
      region) backend_region_fields=$((backend_region_fields + 1)) ;;
      dynamodb_table) backend_lock_fields=$((backend_lock_fields + 1)) ;;
      encrypt) backend_encrypt_fields=$((backend_encrypt_fields + 1)) ;;
      access_key | secret_key | token | profile | shared_credentials_file)
        die "backend configuration must not contain credentials or a credential profile"
        ;;
      *) die "backend configuration contains unsupported field ${backend_field}" ;;
    esac
  done <<<"${BACKEND_CONTENT}"
  [[ "${backend_bucket_fields}" -eq 1 &&
    "${backend_key_fields}" -eq 1 &&
    "${backend_region_fields}" -eq 1 &&
    "${backend_lock_fields}" -eq 1 &&
    "${backend_encrypt_fields}" -eq 1 ]] ||
    die "backend configuration must contain each generated field exactly once"

  PLAN_ARGS+=("-var-file=${CONFIG_FILE}")
else
  EXPECTED_ACCOUNT_ID="${PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID:-}"
  EXPECTED_REGION="${PORTSCANNER_EXPECTED_AWS_REGION:-}"
  [[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] ||
    die "PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID must be a 12-digit AWS account ID"
  [[ "${EXPECTED_REGION}" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] ||
    die "PORTSCANNER_EXPECTED_AWS_REGION must be an AWS Region name"

  for VAR_FILE in "${@:3}"; do
    if [[ "${VAR_FILE}" != /* ]]; then
      VAR_FILE="${ROOT}/${VAR_FILE}"
    fi
    [[ -f "${VAR_FILE}" ]] || die "variable file not found: ${VAR_FILE}"
    PLAN_ARGS+=("-var-file=${VAR_FILE}")
  done
  PLAN_ARGS+=(
    "-var=aws_region=${EXPECTED_REGION}"
    "-var=expected_deployment_account_id=${EXPECTED_ACCOUNT_ID}"
  )
  BACKEND_CONFIG="${TF_BACKEND_CONFIG:-}"
  if [[ -n "${BACKEND_CONFIG}" && "${BACKEND_CONFIG}" != /* ]]; then
    BACKEND_CONFIG="$(pwd -P)/${BACKEND_CONFIG}"
  fi
  if [[ -n "${BACKEND_CONFIG}" && ! -f "${BACKEND_CONFIG}" ]]; then
    die "backend configuration not found: ${BACKEND_CONFIG}"
  fi
fi

for cli_args_name in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply; do
  cli_args_value="${!cli_args_name-}"
  for forbidden_arg in -target -destroy -refresh-only -replace; do
    if [[ "${cli_args_value}" == *"${forbidden_arg}"* ]]; then
      die "${cli_args_name} must not inject ${forbidden_arg} into staged deployment"
    fi
  done
done

ACTUAL_ACCOUNT_ID="$(
  aws sts get-caller-identity \
    --region "${EXPECTED_REGION}" \
    --query Account \
    --output text
)"
[[ "${ACTUAL_ACCOUNT_ID}" == "${EXPECTED_ACCOUNT_ID}" ]] ||
  die "AWS identity mismatch: expected account ${EXPECTED_ACCOUNT_ID}, got ${ACTUAL_ACCOUNT_ID}"

export PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID="${EXPECTED_ACCOUNT_ID}"
export PORTSCANNER_EXPECTED_AWS_REGION="${EXPECTED_REGION}"

INIT_ARGS=("-input=false")
if [[ -n "${BACKEND_CONFIG}" ]]; then
  INIT_ARGS+=("-backend-config=${BACKEND_CONFIG}")
fi
terraform "-chdir=${ROOT}" init "${INIT_ARGS[@]}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portable-portscanner.XXXXXX")"
PLAN_COUNTER=0
IMAGE_ARGS_ADDED=false
EVALUATION_NEEDS_PAUSE=false
EVALUATION_PAUSED=false

cleanup() {
  local status=$?
  local pause_status=0
  trap - EXIT HUP INT TERM
  if [[ "${EVALUATION_NEEDS_PAUSE}" == "true" && "${EVALUATION_PAUSED}" != "true" ]]; then
    log "Evaluation did not complete cleanly; applying pause-canary before exit."
    set +e
    apply_stage pause-canary
    pause_status=$?
    set -e
    if [[ "${pause_status}" -ne 0 ]]; then
      log "ERROR: automatic pause-canary failed; run deploy.sh pause-canary immediately."
      status="${pause_status}"
    fi
  fi
  rm -rf -- "${WORK_DIR}"
  exit "${status}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

ensure_image_inputs() {
  if [[ "${CANONICAL_MODE}" != "true" || "${IMAGE_ARGS_ADDED}" == "true" ]]; then
    return 0
  fi
  require_private_generated_file "${IMAGE_INPUTS}" "generated image input"
  PLAN_ARGS+=("-var-file=${IMAGE_INPUTS}")
  IMAGE_ARGS_ADDED=true
}

set_stage_args() {
  case "$1" in
    foundation)
      STAGE_ARGS=(
        "-var=deploy_runtime=false"
        "-var=run_migration=false"
        "-var=install_operator=false"
        "-var=enable_event_dispatch=false"
        "-var=enable_automatic_inventory=false"
        "-var=canary_mode=false"
      )
      ;;
    runtime)
      STAGE_ARGS=(
        "-var=deploy_runtime=true"
        "-var=run_migration=false"
        "-var=install_operator=false"
        "-var=enable_event_dispatch=false"
        "-var=enable_automatic_inventory=false"
        "-var=canary_mode=false"
      )
      ;;
    migrate | pause)
      STAGE_ARGS=(
        "-var=deploy_runtime=true"
        "-var=run_migration=true"
        "-var=install_operator=true"
        "-var=enable_event_dispatch=false"
        "-var=enable_automatic_inventory=false"
        "-var=canary_mode=false"
      )
      ;;
    pause-canary)
      STAGE_ARGS=(
        "-var=deploy_runtime=true"
        "-var=run_migration=true"
        "-var=install_operator=true"
        "-var=enable_event_dispatch=false"
        "-var=enable_automatic_inventory=false"
        "-var=canary_mode=true"
      )
      ;;
    canary)
      STAGE_ARGS=(
        "-var=deploy_runtime=true"
        "-var=run_migration=true"
        "-var=install_operator=true"
        "-var=enable_event_dispatch=true"
        "-var=enable_automatic_inventory=false"
        "-var=canary_mode=true"
      )
      ;;
    activate)
      STAGE_ARGS=(
        "-var=deploy_runtime=true"
        "-var=run_migration=true"
        "-var=install_operator=true"
        "-var=enable_event_dispatch=true"
        "-var=enable_automatic_inventory=true"
        "-var=canary_mode=false"
      )
      ;;
    *)
      die "unsupported Terraform stage: $1"
      ;;
  esac
}

refresh_state_list() {
  STATE_LIST="$(terraform "-chdir=${ROOT}" state list 2>/dev/null || true)"
}

state_contains() {
  [[ "${STATE_LIST}" == *"$1"* ]]
}

validate_stage_progression() {
  local stage="$1"
  refresh_state_list
  case "${stage}" in
    foundation)
      if state_contains "aws_lambda_function.this" ||
        state_contains "aws_lambda_invocation.migration" ||
        state_contains "helm_release.operator"; then
        die "refusing to roll an existing runtime back to foundation; use a separately reviewed Terraform plan"
      fi
      ;;
    runtime)
      state_contains "aws_ecr_repository.this" ||
        die "foundation state was not found; apply the foundation stage first"
      if state_contains "aws_lambda_invocation.migration" || state_contains "helm_release.operator"; then
        die "refusing to roll a migrated installation back to runtime-paused state"
      fi
      ;;
    migrate)
      state_contains "aws_lambda_function.this" ||
        die "paused runtime state was not found; apply the runtime stage first"
      ;;
    canary | activate)
      state_contains "aws_lambda_invocation.migration" ||
        die "migration state was not found; apply the migrate stage first"
      state_contains "helm_release.operator" ||
        die "operator release state was not found; apply the migrate stage first"
      if [[ "${stage}" == "activate" ]]; then
        require_command jq
        if ! CURRENT_DEPLOYMENT_STATE="$(
          terraform "-chdir=${ROOT}" output -json deployment_state
        )"; then
          die "deployment_state output is unavailable; apply and verify the canary stage first"
        fi
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
          all(.[]; type == "boolean") and
          .runtime_created and
          .migration_run and
          .operator_installed and
          .canary_mode and
          (.automatic_inventory_enabled == false) and
          (.periodic_snapshots_enabled == false) and
          (.periodic_coverage_enabled == false) and
          (.signal_hints_enabled == false) and
          (.processor_reconciliation_enabled == false)
        ' <<<"${CURRENT_DEPLOYMENT_STATE}" >/dev/null; then
          die "activation requires a previously applied canary or pause-canary state"
        fi
      fi
      ;;
    pause | pause-canary)
      state_contains "aws_lambda_invocation.migration" ||
        die "migration state was not found; apply the migrate stage first"
      state_contains "helm_release.operator" ||
        die "operator release state was not found; apply the migrate stage first"
      ;;
  esac
}

validate_pause_plan() {
  local stage="$1"
  local plan_file="$2"
  local plan_json="${WORK_DIR}/${stage}-${PLAN_COUNTER}.json"
  require_command jq
  terraform "-chdir=${ROOT}" show -json "${plan_file}" >"${plan_json}"
  if ! jq -e '
    def disables_mapping_only:
      .type == "aws_lambda_event_source_mapping" and
      .change.before.enabled == true and
      .change.after.enabled == false and
      ((.change.before | del(.enabled)) == (.change.after | del(.enabled)));
    def disables_rule_only:
      .type == "aws_cloudwatch_event_rule" and
      .change.before.state == "ENABLED" and
      .change.after.state == "DISABLED" and
      ((.change.before | del(.state)) == (.change.after | del(.state)));
    [
      .resource_changes[]?
      | select(.mode == "managed")
      | select(.change.actions != ["no-op"])
    ]
    | all(.[];
        (.change.actions == ["update"]) and
        (disables_mapping_only or disables_rule_only)
      )
  ' "${plan_json}" >/dev/null; then
    die "refusing pause plan: it changes resources outside dispatch mappings and rules"
  fi
}

confirm_stage() {
  local stage="$1"
  if [[ "${PORTSCANNER_AUTO_APPROVE:-false}" == "true" ]]; then
    return 0
  fi
  printf 'Type %s to apply this saved plan: ' "${stage}" >&2
  read -r confirmation
  [[ "${confirmation}" == "${stage}" ]] ||
    die "stage not confirmed; saved plan discarded"
}

stage_success_message() {
  case "$1" in
    foundation)
      echo "Foundation applied with all runtime dispatch disabled."
      echo "Build and scan all seven images before running the runtime stage."
      ;;
    runtime)
      echo "Digest-pinned runtime created with mappings, schedules, and EventBridge dispatch paused."
      ;;
    migrate)
      echo "Keyed migration completed and the namespace-scoped operator was installed; dispatch remains paused."
      ;;
    canary)
      echo "One-target queue and stream processing are active; automatic inventory remains paused."
      ;;
    activate)
      echo "Queue and stream processing, schedules, and filtered EC2 hint forwarding are active."
      ;;
    pause | pause-canary)
      echo "Event mappings, schedules, and filtered EC2 hint forwarding are paused; runtime and evidence are retained."
      ;;
  esac
}

apply_stage() {
  local stage="$1"
  local plan_file
  local paused_state

  case "${stage}" in
    runtime | migrate | canary | activate | pause | pause-canary)
      ensure_image_inputs
      ;;
  esac
  set_stage_args "${stage}"
  validate_stage_progression "${stage}"
  PLAN_COUNTER=$((PLAN_COUNTER + 1))
  plan_file="${WORK_DIR}/${PLAN_COUNTER}-${stage}.tfplan"

  terraform "-chdir=${ROOT}" plan \
    -input=false \
    -out="${plan_file}" \
    "${PLAN_ARGS[@]}" \
    "${STAGE_ARGS[@]}"

  case "${stage}" in
    pause | pause-canary)
      validate_pause_plan "${stage}" "${plan_file}"
      ;;
  esac

  confirm_stage "${stage}"
  terraform "-chdir=${ROOT}" apply "${plan_file}"
  case "${stage}" in
    pause | pause-canary)
      paused_state="$(current_deployment_state)"
      if ! jq -e '
        (.dispatch_enabled == false) and
        (.automatic_inventory_enabled == false) and
        (.periodic_snapshots_enabled == false) and
        (.periodic_coverage_enabled == false) and
        (.signal_hints_enabled == false) and
        (.processor_reconciliation_enabled == false)
      ' <<<"${paused_state}" >/dev/null; then
        die "${stage} applied but one or more dispatch/reconciliation controls remain enabled"
      fi
      ;;
  esac
  stage_success_message "${stage}"
}

current_deployment_state() {
  local state_json
  require_command jq
  if ! state_json="$(terraform "-chdir=${ROOT}" output -json deployment_state)"; then
    die "deployment_state output is unavailable; run bootstrap.sh first"
  fi
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
    all(.[]; type == "boolean") and
    ((.migration_run | not) or .runtime_created) and
    ((.operator_installed | not) or .migration_run) and
    ((.dispatch_enabled | not) or .operator_installed) and
    ((.automatic_inventory_enabled | not) or .dispatch_enabled) and
    ((.periodic_snapshots_enabled | not) or .dispatch_enabled) and
    ((.periodic_coverage_enabled | not) or .dispatch_enabled) and
    ((.signal_hints_enabled | not) or .dispatch_enabled) and
    ((.processor_reconciliation_enabled | not) or (.runtime_created and .migration_run)) and
    (
      (.canary_mode | not) or (
        .operator_installed and
        (.automatic_inventory_enabled == false) and
        (.periodic_snapshots_enabled == false) and
        (.periodic_coverage_enabled == false) and
        (.signal_hints_enabled == false) and
        (.processor_reconciliation_enabled == false)
      )
    )
  ' <<<"${state_json}" >/dev/null; then
    die "deployment_state is malformed or violates staged deployment ordering"
  fi
  printf '%s' "${state_json}"
}

run_ready() {
  local state_json
  local pause_stage
  state_json="$(current_deployment_state)"

  if ! jq -e '.runtime_created' <<<"${state_json}" >/dev/null; then
    apply_stage runtime
    state_json="$(current_deployment_state)"
  fi
  if ! jq -e '.migration_run and .operator_installed' <<<"${state_json}" >/dev/null; then
    apply_stage migrate
    state_json="$(current_deployment_state)"
  fi
  if ! jq -e '
    .runtime_created and
    .migration_run and
    .operator_installed
  ' <<<"${state_json}" >/dev/null; then
    die "ready orchestration did not reach installed migrated runtime"
  fi
  if jq -e '
    .dispatch_enabled or
    .automatic_inventory_enabled or
    .periodic_snapshots_enabled or
    .periodic_coverage_enabled or
    .signal_hints_enabled or
    .processor_reconciliation_enabled
  ' <<<"${state_json}" >/dev/null; then
    if jq -e '.canary_mode' <<<"${state_json}" >/dev/null; then
      pause_stage="pause-canary"
    else
      pause_stage="pause"
    fi
    apply_stage "${pause_stage}"
    state_json="$(current_deployment_state)"
  fi
  if ! jq -e '
    (.dispatch_enabled == false) and
    (.automatic_inventory_enabled == false) and
    (.periodic_snapshots_enabled == false) and
    (.periodic_coverage_enabled == false) and
    (.signal_hints_enabled == false) and
    (.processor_reconciliation_enabled == false)
  ' <<<"${state_json}" >/dev/null; then
    die "ready orchestration did not leave dispatch paused"
  fi
  echo "Runtime, migration, and operator are ready; dispatch is paused."
}

ensure_paused_for_destroy() {
  local state_json
  local pause_stage
  state_json="$(current_deployment_state)"
  if jq -e '
    .dispatch_enabled or
    .automatic_inventory_enabled or
    .periodic_snapshots_enabled or
    .periodic_coverage_enabled or
    .signal_hints_enabled or
    .processor_reconciliation_enabled
  ' <<<"${state_json}" >/dev/null; then
    if jq -e '.canary_mode' <<<"${state_json}" >/dev/null; then
      pause_stage="pause-canary"
    else
      pause_stage="pause"
    fi
    apply_stage "${pause_stage}"
    state_json="$(current_deployment_state)"
  fi
  if ! jq -e '
    (.dispatch_enabled == false) and
    (.automatic_inventory_enabled == false) and
    (.periodic_snapshots_enabled == false) and
    (.periodic_coverage_enabled == false) and
    (.signal_hints_enabled == false) and
    (.processor_reconciliation_enabled == false)
  ' <<<"${state_json}" >/dev/null; then
    die "destroy requires a verified paused deployment"
  fi
  PAUSED_STATE_JSON="${state_json}"
}

run_destroy() {
  local state_json
  local destroy_plan
  local confirmation
  [[ "${CANONICAL_MODE}" == "true" && "${ROOT}" == "${CANONICAL_ROOT}" ]] ||
    die "destroy is restricted to the canonical deployment root"
  [[ "${DISPOSABLE}" == "true" ]] ||
    die "destroy refused: environment.retention.disposable must explicitly be true"
  [[ "${DESTROY_DATA_ON_TEARDOWN}" == "true" ]] ||
    die "destroy refused: environment.retention.destroy_data_on_teardown must explicitly be true"

  ensure_paused_for_destroy
  state_json="${PAUSED_STATE_JSON}"
  if jq -e '.runtime_created' <<<"${state_json}" >/dev/null; then
    ensure_image_inputs
  fi
  if jq -e '.operator_installed' <<<"${state_json}" >/dev/null; then
    RETIREMENT_READINESS_HELPER="${PORTSCANNER_CANARY_RETIRE_HELPER:-${SCRIPT_DIR}/retire-canary.sh}"
    [[ -x "${RETIREMENT_READINESS_HELPER}" ]] ||
      die "destroy requires the retirement readiness helper: ${RETIREMENT_READINESS_HELPER}"
    "${RETIREMENT_READINESS_HELPER}" \
      --verify-only \
      --terraform-root "${ROOT}" \
      --environment-config "${CONFIG_FILE}" \
      --backend-config "${BACKEND_CONFIG}" \
      --image-inputs "${IMAGE_INPUTS}"
  fi
  if jq -e '.operator_installed' <<<"${state_json}" >/dev/null; then
    if jq -e '.canary_mode' <<<"${state_json}" >/dev/null; then
      set_stage_args pause-canary
    else
      set_stage_args pause
    fi
  elif jq -e '.runtime_created' <<<"${state_json}" >/dev/null; then
    set_stage_args runtime
  else
    set_stage_args foundation
  fi

  PLAN_COUNTER=$((PLAN_COUNTER + 1))
  destroy_plan="${WORK_DIR}/${PLAN_COUNTER}-destroy.tfplan"
  terraform "-chdir=${ROOT}" plan \
    -destroy \
    -input=false \
    -out="${destroy_plan}" \
    "${PLAN_ARGS[@]}" \
    "${STAGE_ARGS[@]}"
  terraform "-chdir=${ROOT}" show "${destroy_plan}"
  printf 'Type destroy %s to apply this exact saved destroy plan: ' "${ENVIRONMENT_NAME}" >&2
  read -r confirmation
  [[ "${confirmation}" == "destroy ${ENVIRONMENT_NAME}" ]] ||
    die "destroy not confirmed; saved plan discarded"
  terraform "-chdir=${ROOT}" apply "${destroy_plan}"
  echo "Canonical application resources were destroyed."
  echo "The state-bootstrap bucket, lock table, backend configuration, and bootstrap state were retained."
}

case "${STAGE}" in
  foundation | runtime | migrate | canary | activate | pause | pause-canary)
    apply_stage "${STAGE}"
    ;;
  ready)
    run_ready
    ;;
  evaluate)
    run_ready
    CANARY_HELPER="${PORTSCANNER_CANARY_HELPER:-${SCRIPT_DIR}/evaluate-canary.sh}"
    [[ -x "${CANARY_HELPER}" ]] ||
      die "evaluate unavailable: managed-canary trigger/status integration is not installed at ${CANARY_HELPER}; ready completed and dispatch remains paused"
    EVALUATION_NEEDS_PAUSE=true
    apply_stage canary
    "${CANARY_HELPER}" \
      --terraform-root "${ROOT}" \
      --environment-config "${CONFIG_FILE}" \
      --backend-config "${BACKEND_CONFIG}" \
      --image-inputs "${IMAGE_INPUTS}"
    apply_stage pause-canary
    EVALUATION_PAUSED=true
    echo "Managed canary evaluation completed and dispatch returned to pause-canary."
    ;;
  retire-canary)
    CANARY_RETIRE_HELPER="${PORTSCANNER_CANARY_RETIRE_HELPER:-${SCRIPT_DIR}/retire-canary.sh}"
    [[ -x "${CANARY_RETIRE_HELPER}" ]] ||
      die "retire-canary unavailable: managed-canary Terraform retirement integration is not installed at ${CANARY_RETIRE_HELPER}"
    ensure_paused_for_destroy
    "${CANARY_RETIRE_HELPER}" \
      --terraform-root "${ROOT}" \
      --environment-config "${CONFIG_FILE}" \
      --backend-config "${BACKEND_CONFIG}" \
      --image-inputs "${IMAGE_INPUTS}"
    ;;
  destroy)
    run_destroy
    ;;
  *)
    usage
    ;;
esac
