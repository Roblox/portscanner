#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

if ! command -v terraform >/dev/null 2>&1; then
  if [[ "${PORTSCANNER_SKIP_TERRAFORM_VALIDATE:-false}" == "true" ]]; then
    echo "warning: Terraform validation explicitly skipped" >&2
    exit 0
  fi
  echo "terraform is required; set PORTSCANNER_SKIP_TERRAFORM_VALIDATE=true only for an explicit local skip" >&2
  exit 1
fi

terraform fmt -check -recursive "${AWS_DIR}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portable-portscanner-validate.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${WORK_DIR}/plugin-cache}"
mkdir -p "${TF_PLUGIN_CACHE_DIR}"

ROOTS=(
  "${AWS_DIR}/state-bootstrap"
  "${AWS_DIR}/application"
  "${AWS_DIR}/deployment"
  "${AWS_DIR}/member-account"
  "${AWS_DIR}/examples/existing-vpc"
  "${AWS_DIR}/examples/multi-account-central"
  "${AWS_DIR}/examples/member-account"
)

for root in "${ROOTS[@]}"; do
  root_name="$(basename "${root}")"
  export TF_DATA_DIR="${WORK_DIR}/${root_name}-$RANDOM"
  mkdir -p "${TF_DATA_DIR}"

  echo "initializing ${root}"
  lock_file="${root}/.terraform.lock.hcl"
  lock_file_existed=false
  if [[ -f "${lock_file}" ]]; then
    lock_file_existed=true
  fi
  terraform "-chdir=${root}" init -backend=false -input=false
  validate_status=0
  terraform "-chdir=${root}" validate || validate_status=$?
  if [[ "${lock_file_existed}" = false ]]; then
    rm -f "${lock_file}"
  fi
  if [[ "${validate_status}" -ne 0 ]]; then
    exit "${validate_status}"
  fi
done

REPOSITORY_ROOT="$(git -C "${AWS_DIR}" rev-parse --show-toplevel)"
TEST_MODULES=()
while IFS= read -r module; do
  TEST_MODULES+=("${REPOSITORY_ROOT}/${module}")
done < <(
  git -C "${REPOSITORY_ROOT}" ls-files ':(glob)terraform/aws/**/*.tftest.hcl' |
    while IFS= read -r test_file; do
      dirname "${test_file}"
    done |
    LC_ALL=C sort -u
)
if [[ "${#TEST_MODULES[@]}" -eq 0 ]]; then
  echo "no tracked Terraform contract tests were found" >&2
  exit 1
fi

for module in "${TEST_MODULES[@]}"; do
  module_name="$(basename "${module}")"
  export TF_DATA_DIR="${WORK_DIR}/test-${module_name}-$RANDOM"
  mkdir -p "${TF_DATA_DIR}"

  echo "testing ${module}"
  lock_file="${module}/.terraform.lock.hcl"
  lock_file_existed=false
  if [[ -f "${lock_file}" ]]; then
    lock_file_existed=true
  fi
  terraform "-chdir=${module}" init -backend=false -input=false
  test_status=0
  terraform "-chdir=${module}" test || test_status=$?
  if [[ "${lock_file_existed}" = false ]]; then
    rm -f "${lock_file}"
  fi
  if [[ "${test_status}" -ne 0 ]]; then
    exit "${test_status}"
  fi
done

echo "Terraform formatting, deployment-root validation, and contract tests passed."
