#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform is not installed; static validation skipped" >&2
  exit 0
fi

terraform fmt -check -recursive "${AWS_DIR}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portable-portscanner-validate.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${WORK_DIR}/plugin-cache}"
mkdir -p "${TF_PLUGIN_CACHE_DIR}"

ROOTS=(
  "${AWS_DIR}/state-bootstrap"
  "${AWS_DIR}/application"
  "${AWS_DIR}/examples/created-vpc"
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

echo "Terraform formatting and representative root validation passed."
