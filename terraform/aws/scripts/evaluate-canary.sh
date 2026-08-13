#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
set -euo pipefail

usage() {
  echo "usage: $0 --terraform-root PATH --environment-config PATH --backend-config PATH --image-inputs PATH" >&2
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

ROOT=""
CONFIG_FILE=""
BACKEND_CONFIG=""
IMAGE_INPUTS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
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
for path in "${CONFIG_FILE}" "${BACKEND_CONFIG}" "${IMAGE_INPUTS}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || die "required generated/configuration file is unavailable: ${path}"
done
[[ -d "${ROOT}" && -f "${ROOT}/main.tf" ]] || die "invalid Terraform root: ${ROOT}"

for command_name in terraform aws jq mktemp; do
  require_command "${command_name}"
done

ACCOUNT_ID="$(jq -er '.environment.aws.account_id | select(test("^[0-9]{12}$"))' "${CONFIG_FILE}")" ||
  die "environment configuration has no valid AWS account ID"
REGION="$(jq -er '.environment.aws.region | select(test("^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$"))' "${CONFIG_FILE}")" ||
  die "environment configuration has no valid AWS Region"
EXPECTED_SEVERITY="$(jq -er '.environment.managed_canary.expected_finding_severity' "${CONFIG_FILE}")" ||
  die "environment configuration has no managed-canary severity"
[[ "${EXPECTED_SEVERITY}" == "low" ]] ||
  die "managed-canary verification currently requires expected_finding_severity=low"

ACTUAL_ACCOUNT_ID="$(
  aws sts get-caller-identity \
    --region "${REGION}" \
    --query Account \
    --output text
)" || die "AWS identity is unavailable"
[[ "${ACTUAL_ACCOUNT_ID}" == "${ACCOUNT_ID}" ]] ||
  die "AWS identity mismatch: expected ${ACCOUNT_ID}, got ${ACTUAL_ACCOUNT_ID}"

DEPLOYMENT_STATE="$(terraform "-chdir=${ROOT}" output -json deployment_state)" ||
  die "deployment_state output is unavailable"
if ! jq -e '
  .runtime_created and
  .migration_run and
  .operator_installed and
  .dispatch_enabled and
  .canary_mode and
  .managed_canary_enabled and
  (.automatic_inventory_enabled == false) and
  (.periodic_snapshots_enabled == false) and
  (.periodic_coverage_enabled == false) and
  (.signal_hints_enabled == false) and
  (.processor_reconciliation_enabled == false)
' <<<"${DEPLOYMENT_STATE}" >/dev/null; then
  die "managed-canary evaluation requires the active one-target canary stage"
fi

CANARY="$(terraform "-chdir=${ROOT}" output -json managed_canary)" ||
  die "managed_canary output is unavailable"
if ! jq -e --arg account "${ACCOUNT_ID}" --arg region "${REGION}" '
  type == "object" and
  .account_id == $account and
  .region == $region and
  (.network_interface_id | type == "string" and test("^eni-[0-9a-f]+$")) and
  (.instance_id | type == "string" and test("^i-[0-9a-f]+$")) and
  .instance_state == "running" and
  (.public_ip | type == "string" and length > 0) and
  .public_cidr == (.public_ip + "/32") and
  .listener_port == 18080 and
  (.inventory_tag_key | type == "string" and length > 0) and
  (.inventory_tag_value | type == "string" and length > 0)
' <<<"${CANARY}" >/dev/null; then
  die "managed_canary output is malformed or the instance is not running"
fi

SNAPSHOT_INVOCATION="$(
  terraform "-chdir=${ROOT}" output -json managed_canary_snapshot_invocation
)" || die "managed-canary snapshot invocation output is unavailable"
STATUS_INVOCATION="$(
  terraform "-chdir=${ROOT}" output -json managed_canary_status_invocation
)" || die "managed-canary status invocation output is unavailable"

validate_invocation() {
  local invocation="$1"
  local operation="$2"
  jq -e \
    --arg account "${ACCOUNT_ID}" \
    --arg region "${REGION}" \
    --arg operation "${operation}" '
      type == "object" and
      keys == ["function_arn", "function_name", "payload"] and
      (.function_name | type == "string" and length > 0) and
      (.function_arn | type == "string") and
      (.function_arn | test(
        "^arn:[^:]+:lambda:" + $region + ":" + $account +
        ":function:[A-Za-z0-9-_]+$"
      )) and
      .function_arn == (
        (.function_arn | split(":")[0:6] | join(":")) + ":" + .function_name
      ) and
      .payload == {operation: $operation}
    ' <<<"${invocation}" >/dev/null ||
    die "managed-canary ${operation} invocation output is malformed"
}
validate_invocation "${SNAPSHOT_INVOCATION}" "managed-canary"
validate_invocation "${STATUS_INVOCATION}" "managed-canary-status"

TIMEOUT_SECONDS="${PORTSCANNER_CANARY_TIMEOUT_SECONDS:-1800}"
POLL_SECONDS="${PORTSCANNER_CANARY_POLL_SECONDS:-10}"
STABILITY_POLLS="${PORTSCANNER_CANARY_STABILITY_POLLS:-3}"
[[ "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ && "${TIMEOUT_SECONDS}" -ge 60 && "${TIMEOUT_SECONDS}" -le 7200 ]] ||
  die "PORTSCANNER_CANARY_TIMEOUT_SECONDS must be an integer from 60 through 7200"
[[ "${POLL_SECONDS}" =~ ^[0-9]+$ && "${POLL_SECONDS}" -le 300 ]] ||
  die "PORTSCANNER_CANARY_POLL_SECONDS must be an integer from 0 through 300"
[[ "${STABILITY_POLLS}" =~ ^[0-9]+$ && "${STABILITY_POLLS}" -ge 1 && "${STABILITY_POLLS}" -le 12 ]] ||
  die "PORTSCANNER_CANARY_STABILITY_POLLS must be an integer from 1 through 12"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-canary.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM
INVOKE_COUNTER=0
INVOKE_PAYLOAD=""

invoke_lambda() {
  local invocation="$1"
  local label="$2"
  local function_name
  local request
  local response_file
  local metadata

  INVOKE_COUNTER=$((INVOKE_COUNTER + 1))
  function_name="$(jq -er .function_name <<<"${invocation}")"
  request="$(jq -ce .payload <<<"${invocation}")"
  response_file="${WORK_DIR}/${INVOKE_COUNTER}-${label}.json"
  metadata="$(
    aws lambda invoke \
      --function-name "${function_name}" \
      --invocation-type RequestResponse \
      --cli-binary-format raw-in-base64-out \
      --payload "${request}" \
      --region "${REGION}" \
      --output json \
      "${response_file}"
  )" || die "${label} Lambda invocation failed"
  if ! jq -e '
    .StatusCode == 200 and
    (has("FunctionError") | not)
  ' <<<"${metadata}" >/dev/null; then
    die "${label} Lambda reported a function error"
  fi
  jq -e . "${response_file}" >/dev/null 2>&1 ||
    die "${label} Lambda returned a non-JSON payload"
  INVOKE_PAYLOAD="$(<"${response_file}")"
}

validate_snapshot_response() {
  local payload="$1"
  jq -e '
    type == "array" and
    length == 1 and
    .[0] as $summary |
    ($summary | type == "object") and
    $summary.completion == "complete" and
    $summary.targets == 1 and
    ($summary.pages | type == "number" and . >= 1) and
    ($summary.revalidated | type == "number" and . >= 0) and
    ($summary.added | type == "number" and . >= 0) and
    ($summary.changed | type == "number" and . >= 0) and
    ($summary.noop | type == "number" and . >= 0) and
    $summary.removed == 0 and
    $summary.race == 0
  ' <<<"${payload}" >/dev/null ||
    die "managed-canary snapshot did not produce one complete, non-removing target result"
}

validate_status_response() {
  local payload="$1"
  jq -e '
    type == "object" and
    keys == [
      "attempt_count",
      "complete_coverage_count",
      "event_count",
      "low_finding_count",
      "open_exposure_count",
      "operation",
      "ready",
      "status",
      "target_count",
      "unexpected_high_finding_count"
    ] and
    .operation == "managed-canary-status" and
    (.ready | type == "boolean") and
    .status == (if .ready then "ready" else "pending" end) and
    all(
      .target_count,
      .event_count,
      .attempt_count,
      .complete_coverage_count,
      .open_exposure_count,
      .low_finding_count,
      .unexpected_high_finding_count;
      type == "number" and . >= 0 and floor == .
    ) and
    .target_count <= 1 and
    .event_count <= 1 and
    .attempt_count <= 1 and
    .complete_coverage_count <= 1 and
    .open_exposure_count <= 1 and
    .low_finding_count <= 1 and
    .unexpected_high_finding_count == 0
  ' <<<"${payload}" >/dev/null ||
    die "managed-canary status returned an invalid or non-idempotent result"
}

wait_until_ready() {
  local deadline=$((SECONDS + TIMEOUT_SECONDS))
  while ((SECONDS <= deadline)); do
    invoke_lambda "${STATUS_INVOCATION}" "status"
    validate_status_response "${INVOKE_PAYLOAD}"
    if jq -e '.ready' <<<"${INVOKE_PAYLOAD}" >/dev/null; then
      return 0
    fi
    jq -c '{
      status,
      target_count,
      event_count,
      attempt_count,
      complete_coverage_count,
      open_exposure_count,
      low_finding_count
    }' <<<"${INVOKE_PAYLOAD}" >&2
    sleep "${POLL_SECONDS}"
  done
  die "managed-canary finding did not become ready within ${TIMEOUT_SECONDS} seconds"
}

invoke_lambda "${SNAPSHOT_INVOCATION}" "snapshot"
validate_snapshot_response "${INVOKE_PAYLOAD}"
wait_until_ready

# Replay the same trusted snapshot and require a stable one-event/one-attempt
# result. This proves the public evaluation path is idempotent before pause.
invoke_lambda "${SNAPSHOT_INVOCATION}" "snapshot-replay"
validate_snapshot_response "${INVOKE_PAYLOAD}"
for ((poll = 1; poll <= STABILITY_POLLS; poll++)); do
  if ((POLL_SECONDS > 0)); then
    sleep "${POLL_SECONDS}"
  fi
  invoke_lambda "${STATUS_INVOCATION}" "status-stability-${poll}"
  validate_status_response "${INVOKE_PAYLOAD}"
  jq -e '
    .ready and
    .target_count == 1 and
    .event_count == 1 and
    .attempt_count == 1 and
    .complete_coverage_count == 1 and
    .open_exposure_count == 1 and
    .low_finding_count == 1 and
    .unexpected_high_finding_count == 0
  ' <<<"${INVOKE_PAYLOAD}" >/dev/null ||
    die "managed-canary replay changed the effective target, event, attempt, exposure, or finding"
done

echo "Managed canary verified: one targeted TCP 18080 attempt and one low PostgreSQL finding."
