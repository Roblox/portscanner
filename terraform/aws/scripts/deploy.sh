#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
  echo "usage: $0 <terraform-root> <foundation|runtime|migrate|activate> [variables.tfvars]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
command -v terraform >/dev/null 2>&1 || {
  echo "terraform is required" >&2
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
if [[ $# -eq 3 ]]; then
  VAR_FILE="$3"
  if [[ "${VAR_FILE}" != /* ]]; then
    VAR_FILE="${ROOT}/${VAR_FILE}"
  fi
  [[ -f "${VAR_FILE}" ]] || {
    echo "variable file not found: ${VAR_FILE}" >&2
    exit 1
  }
  PLAN_ARGS+=("-var-file=${VAR_FILE}")
fi

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
    )
    ;;
  runtime)
    STAGE_ARGS=(
      "-var=deploy_runtime=true"
      "-var=run_migration=false"
      "-var=install_operator=false"
      "-var=enable_event_dispatch=false"
    )
    ;;
  migrate)
    STAGE_ARGS=(
      "-var=deploy_runtime=true"
      "-var=run_migration=true"
      "-var=install_operator=true"
      "-var=enable_event_dispatch=false"
    )
    ;;
  activate)
    STAGE_ARGS=(
      "-var=deploy_runtime=true"
      "-var=run_migration=true"
      "-var=install_operator=true"
      "-var=enable_event_dispatch=true"
    )
    ;;
  *)
    usage
    ;;
esac

case "${STAGE}" in
  migrate | activate)
    command -v aws >/dev/null 2>&1 || {
      echo "AWS CLI is required for Helm exec authentication during ${STAGE}" >&2
      exit 1
    }
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
  activate)
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
    echo "Verify private EKS and application health before running the activate stage."
    ;;
  activate)
    echo "Event mappings, schedules, and filtered EC2 hint forwarding are active."
    ;;
esac
