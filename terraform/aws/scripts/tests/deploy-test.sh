#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy.sh"
TF_ROOT="${AWS_DIR}/deployment"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-deploy-test.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

FAKE_BIN="${WORK_DIR}/bin"
TF_CALLS="${WORK_DIR}/terraform-calls"
mkdir -p "${FAKE_BIN}"
: >"${TF_CALLS}"

cat >"${FAKE_BIN}/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${TF_CALLS:?}"
operation="${2:-}"
case "${operation}" in
  init)
    ;;
  state)
    [[ "${3:-}" == "list" ]] || exit 91
    if [[ "${FAKE_TF_STATE:-foundation}" == "active" ]]; then
      printf '%s\n' \
        "module.portscanner.module.functions.aws_lambda_invocation.migration[0]" \
        "module.portscanner.module.eks.helm_release.operator[0]"
    fi
    ;;
  plan)
    plan_file=""
    for argument in "$@"; do
      if [[ "${argument}" == -out=* ]]; then
        plan_file="${argument#-out=}"
      fi
    done
    [[ -n "${plan_file}" ]] || exit 92
    : >"${plan_file}"
    ;;
  show)
    case "${FAKE_TF_PAUSE_PLAN:-safe}" in
      unsafe)
        printf '%s\n' '{"resource_changes":[{"mode":"managed","type":"aws_lambda_invocation","change":{"actions":["update"]}}]}'
        ;;
      unsafe-dispatch)
        printf '%s\n' '{"resource_changes":[{"mode":"managed","type":"aws_lambda_event_source_mapping","change":{"actions":["update"],"before":{"enabled":true,"batch_size":10},"after":{"enabled":false,"batch_size":100}}}]}'
        ;;
      safe)
        printf '%s\n' '{"resource_changes":[{"mode":"managed","type":"aws_lambda_event_source_mapping","change":{"actions":["update"],"before":{"enabled":true,"batch_size":10},"after":{"enabled":false,"batch_size":10}}},{"mode":"managed","type":"aws_cloudwatch_event_rule","change":{"actions":["update"],"before":{"state":"ENABLED","schedule_expression":"rate(1 hour)"},"after":{"state":"DISABLED","schedule_expression":"rate(1 hour)"}}}]}'
        ;;
    esac
    ;;
  output)
    [[ "${3:-}" == "-json" && "${4:-}" == "deployment_state" ]] || exit 95
    if [[ "${FAKE_TF_DEPLOYMENT_STATE:-canary}" == "migrated" ]]; then
      printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":false,"canary_mode":false}'
    else
      applied_stage=""
      [[ ! -f "${TF_CALLS:?}.stage" ]] || applied_stage="$(<"${TF_CALLS}.stage")"
      case "${applied_stage}" in
        pause)
          printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":false,"canary_mode":false}'
          ;;
        pause-canary)
          printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":true}'
          ;;
        *)
          printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":true,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":true}'
          ;;
      esac
    fi
    ;;
  apply)
    [[ -f "${3:-}" ]] || exit 93
    case "${3:-}" in
      *pause-canary.tfplan) printf '%s\n' pause-canary >"${TF_CALLS:?}.stage" ;;
      *pause.tfplan) printf '%s\n' pause >"${TF_CALLS:?}.stage" ;;
      *canary.tfplan) printf '%s\n' canary >"${TF_CALLS:?}.stage" ;;
    esac
    ;;
  *)
    echo "unexpected terraform invocation: $*" >&2
    exit 90
    ;;
esac
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "sts" && "${2:-}" == "get-caller-identity" ]]; then
  printf '%s\n' "${FAKE_AWS_ACCOUNT_ID:-123456789012}"
  exit 0
fi
exit 94
EOF
chmod +x "${FAKE_BIN}/terraform" "${FAKE_BIN}/aws"

export PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID="123456789012"
export PORTSCANNER_EXPECTED_AWS_REGION="us-east-1"

FIRST_VARS="${WORK_DIR}/evaluation.tfvars"
SECOND_VARS="${WORK_DIR}/images.tfvars"
BACKEND_CONFIG="${WORK_DIR}/backend.hcl"
: >"${FIRST_VARS}"
: >"${SECOND_VARS}"
: >"${BACKEND_CONFIG}"

PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  TF_BACKEND_CONFIG="${BACKEND_CONFIG}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" foundation "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null

CALLS="$(<"${TF_CALLS}")"
[[ "${CALLS}" == *"init -input=false -backend-config=${BACKEND_CONFIG}"* ]] ||
  fail "backend configuration was not passed to terraform init"
[[ "${CALLS}" == *"-var-file=${FIRST_VARS}"* ]] ||
  fail "first variable file was not passed to terraform plan"
[[ "${CALLS}" == *"-var-file=${SECOND_VARS}"* ]] ||
  fail "second variable file was not passed to terraform plan"
[[ "${CALLS}" == *"-var=aws_region=us-east-1"* ]] ||
  fail "expected Region was not forced into the plan"
[[ "${CALLS}" == *"-var=expected_deployment_account_id=123456789012"* ]] ||
  fail "expected account was not forced into the plan"
[[ "${CALLS}" == *"-var=deploy_runtime=false"* ]] ||
  fail "foundation runtime gate was not forced off"
[[ "${CALLS}" == *"-var=enable_event_dispatch=false"* ]] ||
  fail "foundation dispatch gate was not forced off"
[[ "${CALLS}" == *"-var=enable_automatic_inventory=false"* ]] ||
  fail "foundation automatic inventory gate was not forced off"
[[ "${CALLS}" == *"-var=canary_mode=false"* ]] ||
  fail "foundation canary gate was not forced off"
[[ "${CALLS}" == *"apply "* ]] ||
  fail "saved plan was not applied"

: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" pause "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null

PAUSE_CALLS="$(<"${TF_CALLS}")"
[[ "${PAUSE_CALLS}" == *"-var=run_migration=true"* ]] ||
  fail "pause did not retain migrated runtime state"
[[ "${PAUSE_CALLS}" == *"-var=install_operator=true"* ]] ||
  fail "pause did not retain the operator"
[[ "${PAUSE_CALLS}" == *"-var=enable_event_dispatch=false"* ]] ||
  fail "pause did not disable dispatch"
[[ "${PAUSE_CALLS}" == *"-var=enable_automatic_inventory=false"* ]] ||
  fail "pause did not disable automatic inventory"
[[ "${PAUSE_CALLS}" == *"show -json"* ]] ||
  fail "pause did not inspect the saved plan"

: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" pause-canary "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null
PAUSE_CANARY_CALLS="$(<"${TF_CALLS}")"
[[ "${PAUSE_CANARY_CALLS}" == *"-var=canary_mode=true"* ]] ||
  fail "pause-canary did not retain the fail-closed canary boundary"

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  FAKE_TF_PAUSE_PLAN=unsafe \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" pause "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null 2>&1; then
  fail "pause accepted migration or release-resource changes"
fi

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  FAKE_TF_PAUSE_PLAN=unsafe-dispatch \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" pause "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null 2>&1; then
  fail "pause accepted a non-state dispatch configuration change"
fi

: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" canary "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null

CANARY_CALLS="$(<"${TF_CALLS}")"
[[ "${CANARY_CALLS}" == *"-var=enable_event_dispatch=true"* ]] ||
  fail "canary did not enable the queue and stream pipeline"
[[ "${CANARY_CALLS}" == *"-var=enable_automatic_inventory=false"* ]] ||
  fail "canary enabled automatic inventory"
[[ "${CANARY_CALLS}" == *"-var=canary_mode=true"* ]] ||
  fail "canary boundary was not forced on"

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  FAKE_TF_DEPLOYMENT_STATE=migrated \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" activate "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null 2>&1; then
  fail "activate bypassed the required canary stage"
fi

: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_TF_STATE=active \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" activate "${FIRST_VARS}" "${SECOND_VARS}" \
  >/dev/null

ACTIVATE_CALLS="$(<"${TF_CALLS}")"
[[ "${ACTIVATE_CALLS}" == *"-var=enable_event_dispatch=true"* ]] ||
  fail "activate did not enable the queue and stream pipeline"
[[ "${ACTIVATE_CALLS}" == *"-var=enable_automatic_inventory=true"* ]] ||
  fail "activate did not enable automatic inventory"
[[ "${ACTIVATE_CALLS}" == *"-var=canary_mode=false"* ]] ||
  fail "activate retained canary mode"

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" foundation "${WORK_DIR}/missing.tfvars" \
  >/dev/null 2>&1; then
  fail "missing variable file was accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  TF_CLI_ARGS_plan="-target=unsafe" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" foundation "${FIRST_VARS}" \
  >/dev/null 2>&1; then
  fail "unsafe injected plan arguments were accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  FAKE_AWS_ACCOUNT_ID="222222222222" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" "${TF_ROOT}" foundation "${FIRST_VARS}" \
  >/dev/null 2>&1; then
  fail "unexpected AWS account was accepted"
fi

CANONICAL_CONFIG="${WORK_DIR}/environment.auto.tfvars.json"
CANONICAL_ARTIFACT_ROOT="${WORK_DIR}/artifacts"
CANONICAL_STATE="${WORK_DIR}/canonical-state"
CANONICAL_APPLIES="${WORK_DIR}/canonical-applies"
CANONICAL_ENVIRONMENT="test-eval"
CANONICAL_ACCOUNT="123456789012"
CANONICAL_REGION="us-east-1"
CANONICAL_ARTIFACT_DIR="${CANONICAL_ARTIFACT_ROOT}/${CANONICAL_ENVIRONMENT}/${CANONICAL_ACCOUNT}/${CANONICAL_REGION}"
CANONICAL_BACKEND="${CANONICAL_ARTIFACT_DIR}/backend.hcl"
CANONICAL_IMAGES="${CANONICAL_ARTIFACT_DIR}/images.tfvars"
mkdir -p "${CANONICAL_ARTIFACT_DIR}"

write_canonical_config() {
  local disposable="$1"
  local destroy_data="$2"
  local account_id="${3:-${CANONICAL_ACCOUNT}}"
  local installer_arn="arn:"
  installer_arn+="aws:iam::${account_id}:role/test-installer"
  cat >"${CANONICAL_CONFIG}" <<EOF
{
  "environment": {
    "name": "${CANONICAL_ENVIRONMENT}",
    "aws": {"account_id": "${account_id}", "region": "${CANONICAL_REGION}"},
    "network": {
      "vpc_cidr": "10.64.0.0/20",
      "availability_zones": [],
      "az_count": 2,
      "nat_gateway_mode": "single"
    },
    "runner": {
      "eks_installer_principal_arn": "${installer_arn}",
      "restricted_public_cidr": "198.51.100.10/32"
    },
    "retention": {
      "disposable": ${disposable},
      "destroy_data_on_teardown": ${destroy_data},
      "database_backup_days": 1,
      "lambda_log_days": 7,
      "ecr_untagged_image_days": 7,
      "bucket_expiration_days": {
        "events": 7,
        "results": 7,
        "findings": 30,
        "cloudtrail": 30
      }
    },
    "scanner": {
      "operator_max_concurrent_reconciles": 1,
      "max_concurrent_pods": 1,
      "max_jobs": 4,
      "min_rate": 100,
      "max_rate": 250,
      "architecture": "arm64",
      "node_instance_type": "t4g.medium"
    },
    "managed_canary": {
      "enabled": true,
      "vpc_cidr": "10.255.255.0/28",
      "instance_type": "t4g.nano",
      "listen_port": 18080,
      "expected_finding_severity": "low"
    },
    "integrations": {
      "recurring_inventory_enabled": false,
      "signal_hints_enabled": false,
      "finding_export_enabled": false,
      "config_mode": "disabled",
      "existing_config_aggregator_name": "",
      "snapshot_regions": [],
      "cloudtrail_mode": "disabled",
      "existing_cloudtrail_arn": "",
      "authorized_account_ids": [],
      "allowed_target_cidrs": [],
      "denied_target_cidrs": [],
      "allowed_eni_interface_types": ["interface"],
      "required_target_tag_key": "application",
      "required_target_tag_value": "portscanner"
    }
  }
}
EOF
}

write_backend() {
  local key="${1:-environments/${CANONICAL_ENVIRONMENT}/${CANONICAL_ACCOUNT}/${CANONICAL_REGION}/deployment.tfstate}"
  cat >"${CANONICAL_BACKEND}" <<EOF
bucket         = "test-state-bucket"
key            = "${key}"
region         = "${CANONICAL_REGION}"
dynamodb_table = "test-state-locks"
encrypt        = true
EOF
  chmod 600 "${CANONICAL_BACKEND}"
}

cat >"${FAKE_BIN}/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${TF_CALLS:?}"
operation="${2:-}"
state="$(<"${CANONICAL_STATE:?}")"
case "${operation}" in
  init)
    ;;
  state)
    [[ "${3:-}" == "list" ]] || exit 91
    case "${state}" in
      foundation)
        printf '%s\n' "module.portscanner.module.repositories.aws_ecr_repository.this[\"inventory\"]"
        ;;
      runtime)
        printf '%s\n' \
          "module.portscanner.module.repositories.aws_ecr_repository.this[\"inventory\"]" \
          "module.portscanner.module.functions.aws_lambda_function.this[\"inventory\"]"
        ;;
      ready | active)
        printf '%s\n' \
          "module.portscanner.module.repositories.aws_ecr_repository.this[\"inventory\"]" \
          "module.portscanner.module.functions.aws_lambda_function.this[\"inventory\"]" \
          "module.portscanner.module.functions.aws_lambda_invocation.migration[0]" \
          "module.portscanner.module.eks.helm_release.operator[0]"
        ;;
      destroyed)
        ;;
      *)
        exit 92
        ;;
    esac
    ;;
  output)
    [[ "${3:-}" == "-json" && "${4:-}" == "deployment_state" ]] || exit 93
    case "${state}" in
      foundation)
        printf '%s\n' '{"runtime_created":false,"migration_run":false,"operator_installed":false,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":false}'
        ;;
      runtime)
        printf '%s\n' '{"runtime_created":true,"migration_run":false,"operator_installed":false,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":false}'
        ;;
      ready)
        printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":false}'
        ;;
      active)
        printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":true,"automatic_inventory_enabled":true,"periodic_snapshots_enabled":true,"periodic_coverage_enabled":true,"signal_hints_enabled":true,"processor_reconciliation_enabled":true,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":false}'
        ;;
      *)
        exit 94
        ;;
    esac
    ;;
  plan)
    plan_file=""
    for argument in "$@"; do
      if [[ "${argument}" == -out=* ]]; then
        plan_file="${argument#-out=}"
      fi
    done
    [[ -n "${plan_file}" ]] || exit 95
    : >"${plan_file}"
    ;;
  show)
    if [[ "${3:-}" == "-json" ]]; then
      printf '%s\n' '{"resource_changes":[{"mode":"managed","type":"aws_lambda_event_source_mapping","change":{"actions":["update"],"before":{"enabled":true},"after":{"enabled":false}}}]}'
    else
      printf '%s\n' "saved destroy plan"
    fi
    ;;
  apply)
    plan_file="${3:-}"
    [[ -f "${plan_file}" ]] || exit 96
    printf '%s\n' "${plan_file}" >>"${CANONICAL_APPLIES:?}"
    case "${plan_file}" in
      *-runtime.tfplan) printf '%s\n' runtime >"${CANONICAL_STATE}" ;;
      *-migrate.tfplan | *-pause.tfplan | *-pause-canary.tfplan)
        printf '%s\n' ready >"${CANONICAL_STATE}"
        ;;
      *-destroy.tfplan) printf '%s\n' destroyed >"${CANONICAL_STATE}" ;;
    esac
    ;;
  *)
    echo "unexpected terraform invocation: $*" >&2
    exit 97
    ;;
esac
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "sts" && "${2:-}" == "get-caller-identity" ]]; then
  printf '%s\n' "${FAKE_AWS_ACCOUNT_ID:-123456789012}"
  exit 0
fi
exit 98
EOF
chmod +x "${FAKE_BIN}/terraform" "${FAKE_BIN}/aws"

write_canonical_config true true
write_backend
: >"${CANONICAL_IMAGES}"
chmod 600 "${CANONICAL_IMAGES}"
printf '%s\n' foundation >"${CANONICAL_STATE}"
: >"${CANONICAL_APPLIES}"
: >"${TF_CALLS}"

PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null

[[ "$(<"${CANONICAL_STATE}")" == "ready" ]] ||
  fail "ready orchestration did not reach the paused ready state"
CANONICAL_CALLS="$(<"${TF_CALLS}")"
[[ "${CANONICAL_CALLS}" == *"-chdir=${AWS_DIR}/deployment init"* ]] ||
  fail "canonical invocation did not default to the deployment root"
[[ "${CANONICAL_CALLS}" == *"-backend-config=${CANONICAL_BACKEND}"* ]] ||
  fail "canonical invocation did not use the derived backend"
[[ "${CANONICAL_CALLS}" == *"-var-file=${CANONICAL_CONFIG}"* ]] ||
  fail "canonical invocation did not use the one environment configuration"
[[ "${CANONICAL_CALLS}" == *"-var-file=${CANONICAL_IMAGES}"* ]] ||
  fail "ready did not use generated image inputs"
[[ "${CANONICAL_CALLS}" == *"-runtime.tfplan"* && "${CANONICAL_CALLS}" == *"-migrate.tfplan"* ]] ||
  fail "ready did not orchestrate runtime then migrate"
[[ "${CANONICAL_CALLS}" != *" -target"* ]] ||
  fail "ready used a targeted Terraform operation"

: >"${TF_CALLS}"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_CANARY_HELPER="${WORK_DIR}/missing-canary-helper" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" evaluate >"${WORK_DIR}/evaluate-output" 2>&1; then
  fail "evaluate pretended to succeed without managed-canary/status integration"
fi
EVALUATE_OUTPUT="$(<"${WORK_DIR}/evaluate-output")"
[[ "${EVALUATE_OUTPUT}" == *"managed-canary trigger/status integration is not installed"* ]] ||
  fail "evaluate missing-integration failure was not precise"
[[ "$(<"${CANONICAL_STATE}")" == "ready" ]] ||
  fail "evaluate without runtime integration did not remain paused"
[[ "$(<"${TF_CALLS}")" != *"-canary.tfplan"* ]] ||
  fail "evaluate entered canary before checking the future helper"

CANARY_HELPER_CALLS="${WORK_DIR}/canary-helper-calls"
cat >"${WORK_DIR}/canary-helper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"${CANARY_HELPER_CALLS:?}"
EOF
chmod 755 "${WORK_DIR}/canary-helper"
: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  CANARY_HELPER_CALLS="${CANARY_HELPER_CALLS}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_CANARY_HELPER="${WORK_DIR}/canary-helper" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" evaluate >/dev/null
[[ "$(<"${TF_CALLS}")" == *"-canary.tfplan"* &&
  "$(<"${TF_CALLS}")" == *"-pause-canary.tfplan"* ]] ||
  fail "evaluate did not bracket the canary helper with guarded stages"
[[ "$(<"${CANARY_HELPER_CALLS}")" == *"--terraform-root ${AWS_DIR}/deployment"* &&
  "$(<"${CANARY_HELPER_CALLS}")" == *"--environment-config ${CANONICAL_CONFIG}"* ]] ||
  fail "evaluate did not pass canonical inputs to the canary helper"

printf '%s\n' active >"${CANONICAL_STATE}"
: >"${TF_CALLS}"
PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null
[[ "$(<"${CANONICAL_STATE}")" == "ready" ]] ||
  fail "ready did not safely pause an already active deployment"
[[ "$(<"${TF_CALLS}")" == *"-pause.tfplan"* ]] ||
  fail "ready did not use the guarded pause stage for active state"

write_backend "unsafe/../collision.tfstate"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null 2>&1; then
  fail "canonical deploy accepted a colliding backend key"
fi
write_backend

printf '%s\n' 'profile = "must-not-be-embedded"' >>"${CANONICAL_BACKEND}"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null 2>&1; then
  fail "canonical deploy accepted credentials or a profile in backend configuration"
fi
write_backend

chmod 644 "${CANONICAL_BACKEND}"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null 2>&1; then
  fail "canonical deploy accepted a non-private backend file"
fi
chmod 600 "${CANONICAL_BACKEND}"

printf '%s\n' foundation >"${CANONICAL_STATE}"
chmod 644 "${CANONICAL_IMAGES}"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null 2>&1; then
  fail "ready accepted non-private generated image inputs"
fi
chmod 600 "${CANONICAL_IMAGES}"

write_canonical_config true true "222222222222"
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" ready >/dev/null 2>&1; then
  fail "canonical deploy accepted an AWS identity mismatch"
fi
write_canonical_config true true

write_canonical_config false false
if PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" destroy >/dev/null 2>&1; then
  fail "destroy accepted an environment without disposable retention acknowledgement"
fi

write_canonical_config true true
printf '%s\n' foundation >"${CANONICAL_STATE}"
: >"${CANONICAL_APPLIES}"
if printf '%s\n' wrong-confirmation | PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" destroy >/dev/null 2>&1; then
  fail "destroy accepted an inexact confirmation"
fi
[[ ! -s "${CANONICAL_APPLIES}" ]] ||
  fail "destroy applied after an inexact confirmation"

printf '%s\n' foundation >"${CANONICAL_STATE}"
: >"${CANONICAL_APPLIES}"
: >"${TF_CALLS}"
printf '%s\n' "destroy ${CANONICAL_ENVIRONMENT}" | PATH="${FAKE_BIN}:${PATH}" \
  TF_CALLS="${TF_CALLS}" \
  CANONICAL_STATE="${CANONICAL_STATE}" \
  CANONICAL_APPLIES="${CANONICAL_APPLIES}" \
  PORTSCANNER_CONFIG_FILE="${CANONICAL_CONFIG}" \
  PORTSCANNER_ARTIFACT_ROOT="${CANONICAL_ARTIFACT_ROOT}" \
  PORTSCANNER_AUTO_APPROVE=true \
  "${DEPLOY_SCRIPT}" destroy >/dev/null
[[ "$(<"${CANONICAL_STATE}")" == "destroyed" ]] ||
  fail "exactly confirmed canonical destroy did not apply"
DESTROY_CALLS="$(<"${TF_CALLS}")"
[[ "${DESTROY_CALLS}" == *"plan -destroy -input=false"* ]] ||
  fail "destroy did not save an explicit destroy plan"
[[ "${DESTROY_CALLS}" == *"show "*"destroy.tfplan"* ]] ||
  fail "destroy did not show the exact saved plan before applying"
[[ "${DESTROY_CALLS}" != *"/state-bootstrap"* ]] ||
  fail "destroy attempted to operate on state-bootstrap"

echo "deploy helper tests passed"
