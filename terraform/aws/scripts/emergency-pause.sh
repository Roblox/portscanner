#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
  echo "usage: $0 <terraform-root>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
for command_name in aws python3 terraform; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "${command_name} is required" >&2
    exit 1
  }
done

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

ROOT_ARG="$1"
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
terraform "-chdir=${ROOT}" init "${INIT_ARGS[@]}" >/dev/null

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-emergency-pause.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

terraform "-chdir=${ROOT}" output -json emergency_pause_controls >"${WORK_DIR}/controls.json"
python3 - "${WORK_DIR}" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
controls = json.loads((root / "controls.json").read_text(encoding="utf-8"))
if not isinstance(controls, dict):
    raise SystemExit("emergency_pause_controls must be an object")

account_id = controls.get("account_id")
region = controls.get("region")
mappings = controls.get("event_source_mapping_uuids")
rules = controls.get("event_rule_controls")
if not isinstance(account_id, str) or re.fullmatch(r"[0-9]{12}", account_id) is None:
    raise SystemExit("emergency pause output has an invalid account_id")
if not isinstance(region, str) or re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", region) is None:
    raise SystemExit("emergency pause output has an invalid region")
if not isinstance(mappings, list) or not all(
    isinstance(value, str)
    and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    )
    for value in mappings
):
    raise SystemExit("emergency pause output has invalid event-source mapping UUIDs")
if not isinstance(rules, list) or not all(
    isinstance(value, dict)
    and set(value) == {"name", "event_bus_name"}
    and isinstance(value["name"], str)
    and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value["name"])
    and isinstance(value["event_bus_name"], str)
    and re.fullmatch(r"[A-Za-z0-9._/-]{1,256}", value["event_bus_name"])
    for value in rules
):
    raise SystemExit("emergency pause output has invalid EventBridge rule controls")
rule_keys = [(value["event_bus_name"], value["name"]) for value in rules]
if len(mappings) != len(set(mappings)) or len(rule_keys) != len(set(rule_keys)):
    raise SystemExit("emergency pause output contains duplicate controls")
if not mappings and not rules:
    raise SystemExit("no deployed dispatch controls were found in Terraform state")

(root / "account").write_text(account_id, encoding="utf-8")
(root / "region").write_text(region, encoding="utf-8")
(root / "mappings").write_text("".join(f"{value}\n" for value in sorted(mappings)), encoding="utf-8")
(root / "rules").write_text(
    "".join(f"{bus}\t{name}\n" for bus, name in sorted(rule_keys)),
    encoding="utf-8",
)
PY

STATE_ACCOUNT_ID="$(<"${WORK_DIR}/account")"
STATE_REGION="$(<"${WORK_DIR}/region")"
[[ "${STATE_ACCOUNT_ID}" == "${EXPECTED_ACCOUNT_ID}" ]] || {
  echo "Terraform state account mismatch: expected ${EXPECTED_ACCOUNT_ID}, got ${STATE_ACCOUNT_ID}" >&2
  exit 1
}
[[ "${STATE_REGION}" == "${EXPECTED_REGION}" ]] || {
  echo "Terraform state Region mismatch: expected ${EXPECTED_REGION}, got ${STATE_REGION}" >&2
  exit 1
}

wait_for_mapping_disabled() {
  local mapping_uuid="$1"
  local attempt state
  attempt=0
  while ((attempt < 60)); do
    state="$(
      aws lambda get-event-source-mapping \
        --uuid "${mapping_uuid}" \
        --region "${EXPECTED_REGION}" \
        --query State \
        --output text
    )"
    if [[ "${state}" == "Disabled" ]]; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "event-source mapping ${mapping_uuid} did not become Disabled" >&2
  return 1
}

mapping_count=0
while IFS= read -r mapping_uuid; do
  [[ -n "${mapping_uuid}" ]] || continue
  state="$(
    aws lambda get-event-source-mapping \
      --uuid "${mapping_uuid}" \
      --region "${EXPECTED_REGION}" \
      --query State \
      --output text
  )"
  if [[ "${state}" != "Disabled" && "${state}" != "Disabling" ]]; then
    aws lambda update-event-source-mapping \
      --uuid "${mapping_uuid}" \
      --no-enabled \
      --region "${EXPECTED_REGION}" >/dev/null
  fi
  wait_for_mapping_disabled "${mapping_uuid}"
  mapping_count=$((mapping_count + 1))
done <"${WORK_DIR}/mappings"

rule_count=0
while IFS=$'\t' read -r event_bus_name rule_name; do
  [[ -n "${event_bus_name}" && -n "${rule_name}" ]] || continue
  state="$(
    aws events describe-rule \
      --name "${rule_name}" \
      --event-bus-name "${event_bus_name}" \
      --region "${EXPECTED_REGION}" \
      --query State \
      --output text
  )"
  if [[ "${state}" != "DISABLED" ]]; then
    aws events disable-rule \
      --name "${rule_name}" \
      --event-bus-name "${event_bus_name}" \
      --region "${EXPECTED_REGION}"
  fi
  state="$(
    aws events describe-rule \
      --name "${rule_name}" \
      --event-bus-name "${event_bus_name}" \
      --region "${EXPECTED_REGION}" \
      --query State \
      --output text
  )"
  [[ "${state}" == "DISABLED" ]] || {
    echo "EventBridge rule ${rule_name} did not become DISABLED" >&2
    exit 1
  }
  rule_count=$((rule_count + 1))
done <"${WORK_DIR}/rules"

echo "Emergency dispatch pause verified: ${mapping_count} mappings and ${rule_count} rules disabled."
echo "This stops new AWS dispatch; it does not terminate scanner Jobs already running in EKS."
