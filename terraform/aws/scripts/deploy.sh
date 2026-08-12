#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
  echo "usage: $0 <terraform-root> <foundation|runtime|migrate|canary|activate|pause|pause-canary> [variables.tfvars ...]" >&2
  exit 2
}

[[ $# -ge 2 ]] || usage
command -v terraform >/dev/null 2>&1 || {
  echo "terraform is required" >&2
  exit 1
}
command -v aws >/dev/null 2>&1 || {
  echo "AWS CLI is required for deployment identity checks" >&2
  exit 1
}

EXPECTED_ACCOUNT_ID="${PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID:-}"
EXPECTED_REGION="${PORTSCANNER_EXPECTED_AWS_REGION:-}"
[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] || {
  echo "PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID must be a 12-digit AWS account ID" >&2
  exit 1
}
[[ "${EXPECTED_REGION}" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] || {
  echo "PORTSCANNER_EXPECTED_AWS_REGION must be an AWS Region name" >&2
  exit 1
}

ACTUAL_ACCOUNT_ID="$(
  aws sts get-caller-identity \
    --region "${EXPECTED_REGION}" \
    --query Account \
    --output text
)"
[[ "${ACTUAL_ACCOUNT_ID}" == "${EXPECTED_ACCOUNT_ID}" ]] || {
  echo "AWS identity mismatch: expected account ${EXPECTED_ACCOUNT_ID}, got ${ACTUAL_ACCOUNT_ID}" >&2
  exit 1
}

ROOT_ARG="$1"
STAGE="$2"

if [[ "${ROOT_ARG}" = /* ]]; then
  ROOT="${ROOT_ARG}"
else
  ROOT="$(pwd)/${ROOT_ARG}"
fi
ROOT="$(CDPATH= cd -- "${ROOT}" && pwd)"

case "${ROOT}/" in
  "${AWS_DIR}/"*) ;;
  *)
    echo "terraform root must remain under ${AWS_DIR}" >&2
    exit 1
    ;;
esac

[[ -f "${ROOT}/main.tf" ]] || {
  echo "${ROOT} is not a Terraform root with main.tf" >&2
  exit 1
}

for cli_args_name in TF_CLI_ARGS TF_CLI_ARGS_plan TF_CLI_ARGS_apply; do
  cli_args_value="${!cli_args_name-}"
  for forbidden_arg in -target -destroy -refresh-only -replace; do
    if [[ "${cli_args_value}" == *"${forbidden_arg}"* ]]; then
      echo "${cli_args_name} must not inject ${forbidden_arg} into staged deployment" >&2
      exit 1
    fi
  done
done

PLAN_ARGS=()
for VAR_FILE in "${@:3}"; do
  if [[ "${VAR_FILE}" != /* ]]; then
    VAR_FILE="${ROOT}/${VAR_FILE}"
  fi
  [[ -f "${VAR_FILE}" ]] || {
    echo "variable file not found: ${VAR_FILE}" >&2
    exit 1
  }
  PLAN_ARGS+=("-var-file=${VAR_FILE}")
done
PLAN_ARGS+=(
  "-var=aws_region=${EXPECTED_REGION}"
  "-var=expected_deployment_account_id=${EXPECTED_ACCOUNT_ID}"
)

INIT_ARGS=("-input=false")
if [[ -n "${TF_BACKEND_CONFIG:-}" ]]; then
  BACKEND_CONFIG="${TF_BACKEND_CONFIG}"
  if [[ "${BACKEND_CONFIG}" != /* ]]; then
    BACKEND_CONFIG="$(pwd)/${BACKEND_CONFIG}"
  fi
  [[ -f "${BACKEND_CONFIG}" ]] || {
    echo "backend configuration not found: ${BACKEND_CONFIG}" >&2
    exit 1
  }
  INIT_ARGS+=("-backend-config=${BACKEND_CONFIG}")
fi

case "${STAGE}" in
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
    usage
    ;;
esac

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portable-portscanner.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
PLAN_FILE="${WORK_DIR}/${STAGE}.tfplan"

terraform "-chdir=${ROOT}" init "${INIT_ARGS[@]}"

STATE_LIST="$(terraform "-chdir=${ROOT}" state list 2>/dev/null || true)"
state_contains() {
  [[ "${STATE_LIST}" == *"$1"* ]]
}

case "${STAGE}" in
  foundation)
    if state_contains "aws_lambda_function.this" || state_contains "aws_lambda_invocation.migration" || state_contains "helm_release.operator"; then
      echo "refusing to roll an existing runtime back to foundation; use a separately reviewed Terraform plan" >&2
      exit 1
    fi
    ;;
  runtime)
    state_contains "aws_ecr_repository.this" || {
      echo "foundation state was not found; apply the foundation stage first" >&2
      exit 1
    }
    if state_contains "aws_lambda_invocation.migration" || state_contains "helm_release.operator"; then
      echo "refusing to roll a migrated installation back to runtime-paused state" >&2
      exit 1
    fi
    ;;
  migrate)
    state_contains "aws_lambda_function.this" || {
      echo "paused runtime state was not found; apply the runtime stage first" >&2
      exit 1
    }
    ;;
  canary | activate)
    state_contains "aws_lambda_invocation.migration" || {
      echo "migration state was not found; apply the migrate stage first" >&2
      exit 1
    }
    state_contains "helm_release.operator" || {
      echo "operator release state was not found; apply the migrate stage first" >&2
      exit 1
    }
    if [[ "${STAGE}" == "activate" ]]; then
      command -v jq >/dev/null 2>&1 || {
        echo "jq is required to verify the canary stage before activation" >&2
        exit 1
      }
      if ! CURRENT_DEPLOYMENT_STATE="$(
        terraform "-chdir=${ROOT}" output -json deployment_state
      )"; then
        echo "deployment_state output is unavailable; apply and verify the canary stage first" >&2
        exit 1
      fi
      if ! jq -e '
        type == "object" and
        keys == ["automatic_inventory_enabled", "canary_mode", "dispatch_enabled", "migration_run", "operator_installed", "runtime_created"] and
        all(.[]; type == "boolean") and
        .runtime_created and
        .migration_run and
        .operator_installed and
        .canary_mode and
        (.automatic_inventory_enabled == false)
      ' <<<"${CURRENT_DEPLOYMENT_STATE}" >/dev/null; then
        echo "activation requires a previously applied canary or pause-canary state" >&2
        exit 1
      fi
    fi
    ;;
  pause | pause-canary)
    state_contains "aws_lambda_invocation.migration" || {
      echo "migration state was not found; apply the migrate stage first" >&2
      exit 1
    }
    state_contains "helm_release.operator" || {
      echo "operator release state was not found; apply the migrate stage first" >&2
      exit 1
    }
    ;;
esac

terraform "-chdir=${ROOT}" plan \
  -input=false \
  -out="${PLAN_FILE}" \
  "${PLAN_ARGS[@]}" \
  "${STAGE_ARGS[@]}"

case "${STAGE}" in
  pause | pause-canary)
    command -v jq >/dev/null 2>&1 || {
      echo "jq is required to validate a pause plan" >&2
      exit 1
    }
    PLAN_JSON="${WORK_DIR}/${STAGE}.json"
    terraform "-chdir=${ROOT}" show -json "${PLAN_FILE}" >"${PLAN_JSON}"
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
    ' "${PLAN_JSON}" >/dev/null; then
      echo "refusing pause plan: it changes resources outside dispatch mappings and rules" >&2
      exit 1
    fi
    ;;
esac

if [[ "${PORTSCANNER_AUTO_APPROVE:-false}" != "true" ]]; then
  printf 'Type %s to apply this saved plan: ' "${STAGE}"
  read -r CONFIRMATION
  if [[ "${CONFIRMATION}" != "${STAGE}" ]]; then
    echo "stage not confirmed; saved plan discarded" >&2
    exit 1
  fi
fi

terraform "-chdir=${ROOT}" apply "${PLAN_FILE}"

case "${STAGE}" in
  foundation)
    echo "Foundation applied with all runtime dispatch disabled."
    echo "Build and scan inventory, generator, parser, processor, migrator, operator, and scanner images externally."
    echo "Push them to repository_urls and record immutable sha256 digests before running the runtime stage."
    ;;
  runtime)
    echo "Digest-pinned runtime created with mappings, schedules, and EventBridge dispatch paused."
    echo "Review the plan and migration checksum before running the migrate stage."
    ;;
  migrate)
    echo "Keyed migration completed and the namespace-scoped operator was installed; dispatch remains paused."
    echo "Verify EKS and application health before running the canary stage."
    ;;
  canary)
    echo "One-target priority/result and stream processing are active; signal/coverage consumers, schedules, and EventBridge inventory hints remain paused."
    echo "Invoke the snapshot Lambda once with an exact account_id, region, and target_public_ipv4, then return to the pause-canary stage."
    ;;
  activate)
    echo "Queue and stream processing, schedules, and filtered EC2 hint forwarding are active."
    ;;
  pause | pause-canary)
    echo "Event mappings, schedules, and filtered EC2 hint forwarding are paused; runtime and evidence are retained."
    ;;
esac
