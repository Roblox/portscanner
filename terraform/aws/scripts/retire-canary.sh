#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
set -euo pipefail

usage() {
  echo "usage: $0 [--verify-only] --terraform-root PATH --environment-config PATH --backend-config PATH --image-inputs PATH" >&2
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

file_mode() {
  if stat -f '%Lp' "$1" 2>/dev/null; then
    return
  fi
  stat -c '%a' "$1"
}

ROOT=""
CONFIG_FILE=""
BACKEND_CONFIG=""
IMAGE_INPUTS=""
VERIFY_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only)
      VERIFY_ONLY=true
      shift
      ;;
    --terraform-root)
      [[ $# -ge 2 ]] || usage
      ROOT="$2"
      shift 2
      ;;
    --environment-config)
      [[ $# -ge 2 ]] || usage
      CONFIG_FILE="$2"
      shift 2
      ;;
    --backend-config)
      [[ $# -ge 2 ]] || usage
      BACKEND_CONFIG="$2"
      shift 2
      ;;
    --image-inputs)
      [[ $# -ge 2 ]] || usage
      IMAGE_INPUTS="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "${ROOT}" && -n "${CONFIG_FILE}" && -n "${BACKEND_CONFIG}" && -n "${IMAGE_INPUTS}" ]] ||
  usage
[[ -d "${ROOT}" && -f "${ROOT}/main.tf" ]] || die "invalid Terraform root: ${ROOT}"
[[ -f "${CONFIG_FILE}" && ! -L "${CONFIG_FILE}" ]] ||
  die "environment configuration is unavailable"
for generated in "${BACKEND_CONFIG}" "${IMAGE_INPUTS}"; do
  [[ -f "${generated}" && ! -L "${generated}" && "$(file_mode "${generated}")" == "600" ]] ||
    die "generated deployment input must be a mode-0600 regular file: ${generated}"
done

for command_name in terraform aws jq kubectl mktemp; do
  require_command "${command_name}"
done

ACCOUNT_ID="$(jq -er '.environment.aws.account_id | select(test("^[0-9]{12}$"))' "${CONFIG_FILE}")" ||
  die "environment configuration has no valid AWS account ID"
REGION="$(jq -er '.environment.aws.region | select(test("^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$"))' "${CONFIG_FILE}")" ||
  die "environment configuration has no valid AWS Region"
ENVIRONMENT_NAME="$(jq -er '.environment.name | select(test("^[a-z][a-z0-9-]{1,19}$"))' "${CONFIG_FILE}")" ||
  die "environment configuration has no valid environment name"
if [[ "${VERIFY_ONLY}" != "true" &&
  "$(jq -er '.environment.managed_canary.enabled | tostring' "${CONFIG_FILE}")" != "false" ]]; then
  die "set environment.managed_canary.enabled=false in the environment file before retirement"
fi

ACTUAL_ACCOUNT_ID="$(
  aws sts get-caller-identity \
    --region "${REGION}" \
    --query Account \
    --output text
)" || die "AWS identity is unavailable"
[[ "${ACTUAL_ACCOUNT_ID}" == "${ACCOUNT_ID}" ]] ||
  die "AWS identity mismatch: expected ${ACCOUNT_ID}, got ${ACTUAL_ACCOUNT_ID}"

terraform "-chdir=${ROOT}" init \
  -input=false \
  "-backend-config=${BACKEND_CONFIG}" >/dev/null

STATE="$(terraform "-chdir=${ROOT}" output -json deployment_state)" ||
  die "deployment_state output is unavailable"
if ! jq -e '
  .runtime_created and
  .migration_run and
  .operator_installed and
  (.dispatch_enabled == false) and
  (.automatic_inventory_enabled == false) and
  (.periodic_snapshots_enabled == false) and
  (.periodic_coverage_enabled == false) and
  (.signal_hints_enabled == false) and
  (.processor_reconciliation_enabled == false)
' <<<"${STATE}" >/dev/null; then
  die "managed-canary retirement requires a fully paused installed deployment"
fi
if [[ "${VERIFY_ONLY}" != "true" ]] &&
  jq -e '.managed_canary_enabled == false' <<<"${STATE}" >/dev/null; then
  echo "Managed canary is already retired."
  exit 0
fi

CURRENT_FINGERPRINT="$(
  terraform "-chdir=${ROOT}" output -raw retirement_configuration_fingerprint
)" || die "retirement configuration fingerprint is unavailable"
[[ "${CURRENT_FINGERPRINT}" =~ ^[0-9a-f]{64}$ ]] ||
  die "current retirement configuration fingerprint is malformed"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-retire-canary.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

QUEUE_URLS="$(terraform "-chdir=${ROOT}" output -json queue_urls)" ||
  die "queue_urls output is unavailable"
if ! jq -e 'type == "object" and all(.[]; type == "string" and length > 0)' \
  <<<"${QUEUE_URLS}" >/dev/null; then
  die "queue_urls output is malformed"
fi

QUEUE_STABILITY_POLLS="${PORTSCANNER_RETIRE_QUEUE_POLLS:-2}"
QUEUE_POLL_SECONDS="${PORTSCANNER_RETIRE_QUEUE_POLL_SECONDS:-5}"
[[ "${QUEUE_STABILITY_POLLS}" =~ ^[0-9]+$ &&
  "${QUEUE_STABILITY_POLLS}" -ge 2 &&
  "${QUEUE_STABILITY_POLLS}" -le 12 ]] ||
  die "PORTSCANNER_RETIRE_QUEUE_POLLS must be an integer from 2 through 12"
[[ "${QUEUE_POLL_SECONDS}" =~ ^[0-9]+$ && "${QUEUE_POLL_SECONDS}" -le 300 ]] ||
  die "PORTSCANNER_RETIRE_QUEUE_POLL_SECONDS must be an integer from 0 through 300"

for ((poll = 1; poll <= QUEUE_STABILITY_POLLS; poll++)); do
  while IFS= read -r queue_url; do
    ATTRIBUTES="$(
      aws sqs get-queue-attributes \
        --queue-url "${queue_url}" \
        --attribute-names \
          ApproximateNumberOfMessages \
          ApproximateNumberOfMessagesNotVisible \
          ApproximateNumberOfMessagesDelayed \
        --region "${REGION}" \
        --query Attributes \
        --output json
    )" || die "could not inspect queue readiness"
    if ! jq -e '
      type == "object" and
      ((.ApproximateNumberOfMessages // "0") | tonumber) == 0 and
      ((.ApproximateNumberOfMessagesNotVisible // "0") | tonumber) == 0 and
      ((.ApproximateNumberOfMessagesDelayed // "0") | tonumber) == 0
    ' <<<"${ATTRIBUTES}" >/dev/null; then
      die "all queues must be drained before releasing the managed-canary EIP"
    fi
  done < <(jq -r '.[]' <<<"${QUEUE_URLS}")
  if ((poll < QUEUE_STABILITY_POLLS && QUEUE_POLL_SECONDS > 0)); then
    sleep "${QUEUE_POLL_SECONDS}"
  fi
done

CLUSTER_NAME="$(terraform "-chdir=${ROOT}" output -raw eks_cluster_name)" ||
  die "eks_cluster_name output is unavailable"
NAMESPACE="$(terraform "-chdir=${ROOT}" output -raw operator_namespace)" ||
  die "operator_namespace output is unavailable"
[[ "${CLUSTER_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]+$ ]] ||
  die "EKS cluster name is malformed"
[[ "${NAMESPACE}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
  die "operator namespace is malformed"

KUBECONFIG_FILE="${WORK_DIR}/kubeconfig"
aws eks update-kubeconfig \
  --name "${CLUSTER_NAME}" \
  --region "${REGION}" \
  --alias portscanner-retire-canary \
  --kubeconfig "${KUBECONFIG_FILE}" >/dev/null ||
  die "could not create the temporary EKS kubeconfig"
chmod 600 "${KUBECONFIG_FILE}"

JOBS="$(
  kubectl \
    --kubeconfig "${KUBECONFIG_FILE}" \
    --namespace "${NAMESPACE}" \
    get jobs \
    --selector app.kubernetes.io/name=portscanner,app.kubernetes.io/component=scanner \
    --output json
)" || die "could not inspect scanner Jobs"
if ! jq -e '
  type == "object" and
  (.items | type == "array") and
  all(
    .items[];
    ((.status.active // 0) == 0) and
    any(
      .status.conditions[]?;
      (.status == "True") and (.type == "Complete" or .type == "Failed")
    )
  )
' <<<"${JOBS}" >/dev/null; then
  die "all scanner Jobs must be terminal before releasing the managed-canary EIP"
fi

SCANNERS="$(
  kubectl \
    --kubeconfig "${KUBECONFIG_FILE}" \
    --namespace "${NAMESPACE}" \
    get scanners.scanning.portscanner.io \
    --output json
)" || die "could not inspect Scanner resources"
if ! jq -e '
  type == "object" and
  (.items | type == "array") and
  all(
    .items[];
    (.status.outcome // "") as $outcome |
    $outcome == "Succeeded" or
    $outcome == "Failed" or
    $outcome == "Cancelled" or
    $outcome == "Expired"
  )
' <<<"${SCANNERS}" >/dev/null; then
  die "all Scanner resources must be terminal before releasing the managed-canary EIP"
fi

if [[ "${VERIFY_ONLY}" == "true" ]]; then
  echo "Retirement readiness verified: queues are drained and scanner work is terminal."
  exit 0
fi

PLAN_FILE="${WORK_DIR}/retire-canary.tfplan"
PLAN_JSON="${WORK_DIR}/retire-canary.json"
terraform "-chdir=${ROOT}" plan \
  -input=false \
  -out="${PLAN_FILE}" \
  "-var-file=${CONFIG_FILE}" \
  "-var-file=${IMAGE_INPUTS}" \
  -var=deploy_runtime=true \
  -var=run_migration=true \
  -var=install_operator=true \
  -var=enable_event_dispatch=false \
  -var=enable_automatic_inventory=false \
  -var=canary_mode=false
terraform "-chdir=${ROOT}" show -json "${PLAN_FILE}" >"${PLAN_JSON}"

PLANNED_FINGERPRINT="$(
  jq -er '.planned_values.outputs.retirement_configuration_fingerprint.value' "${PLAN_JSON}"
)" || die "retirement plan has no configuration fingerprint"
[[ "${PLANNED_FINGERPRINT}" == "${CURRENT_FINGERPRINT}" ]] ||
  die "retirement plan changes environment settings other than managed_canary.enabled"

if ! jq -e '
  [
    .resource_changes[]?
    | select(.mode == "managed")
    | select(.change.actions != ["no-op"])
  ] as $changes
  | ($changes | length) > 0
  and any(
    $changes[];
    .address == "module.portscanner.module.managed_canary[0].aws_eip.this"
    and .change.actions == ["delete"]
  )
  and any(
    $changes[];
    .address == "module.portscanner.module.managed_canary[0].aws_instance.this"
    and .change.actions == ["delete"]
  )
  and all(
    $changes[];
    if .change.actions == ["delete"] then
      (.address | startswith("module.portscanner.module.managed_canary[0]."))
    elif .change.actions == ["update"] then
      (
        .address == "terraform_data.canonical_configuration" or
        .address == "module.portscanner.terraform_data.deployment_validation" or
        (.address | startswith("module.portscanner.module.functions.aws_lambda_function.this[")) or
        .address == "module.portscanner.module.eks.helm_release.operator[0]"
      )
    else
      false
    end
  )
  and (
    .planned_values.outputs.deployment_state.value
    | .managed_canary_enabled == false
    and .canary_mode == false
    and .dispatch_enabled == false
    and .automatic_inventory_enabled == false
    and .periodic_snapshots_enabled == false
    and .periodic_coverage_enabled == false
    and .signal_hints_enabled == false
    and .processor_reconciliation_enabled == false
  )
' "${PLAN_JSON}" >/dev/null; then
  die "retirement plan contains a change outside the reviewed managed-canary boundary"
fi

terraform "-chdir=${ROOT}" show "${PLAN_FILE}"
if [[ "${PORTSCANNER_AUTO_APPROVE:-false}" != "true" ]]; then
  printf 'Type retire-canary %s to apply this exact saved plan: ' "${ENVIRONMENT_NAME}" >&2
  read -r confirmation
  [[ "${confirmation}" == "retire-canary ${ENVIRONMENT_NAME}" ]] ||
    die "managed-canary retirement not confirmed; saved plan discarded"
fi
terraform "-chdir=${ROOT}" apply "${PLAN_FILE}"

RETIRED_STATE="$(terraform "-chdir=${ROOT}" output -json deployment_state)" ||
  die "deployment_state output is unavailable after retirement"
RETIRED_CANARY="$(terraform "-chdir=${ROOT}" output -json managed_canary)" ||
  die "managed_canary output is unavailable after retirement"
jq -e '
  .managed_canary_enabled == false and
  .canary_mode == false and
  .dispatch_enabled == false
' <<<"${RETIRED_STATE}" >/dev/null ||
  die "managed-canary retirement did not leave the deployment paused"
jq -e '. == null' <<<"${RETIRED_CANARY}" >/dev/null ||
  die "managed-canary resources remain in Terraform output after retirement"

echo "Managed canary retired after queue, Job, Scanner, and saved-plan verification."
