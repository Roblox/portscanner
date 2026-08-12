#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
PAUSE_SCRIPT="${SCRIPT_DIR}/emergency-pause.sh"
TF_ROOT="${AWS_DIR}/examples/created-vpc"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-emergency-pause-test.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

FAKE_BIN="${WORK_DIR}/bin"
AWS_CALLS="${WORK_DIR}/aws-calls"
TF_CALLS="${WORK_DIR}/terraform-calls"
mkdir -p "${FAKE_BIN}"
: >"${AWS_CALLS}"
: >"${TF_CALLS}"

cat >"${FAKE_BIN}/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TF_CALLS:?}"
case "${2:-}" in
  init)
    ;;
  output)
    [[ "${3:-}" == "-json" && "${4:-}" == "emergency_pause_controls" ]] || exit 91
    printf '{"account_id":"%s","region":"us-east-2","event_source_mapping_uuids":["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"],"event_rule_controls":[{"name":"portscanner-central","event_bus_name":"portscanner-bus"},{"name":"portscanner-snapshot","event_bus_name":"default"}]}\n' "${FAKE_STATE_ACCOUNT:-123456789012}"
    ;;
  *)
    exit 92
    ;;
esac
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${AWS_CALLS:?}"
service="${1:-}"
operation="${2:-}"
argument_value() {
  local wanted="$1"
  shift
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "${wanted}" ]]; then
      printf '%s' "$2"
      return 0
    fi
    shift
  done
  return 1
}
case "${service}/${operation}" in
  sts/get-caller-identity)
    printf '%s\n' "${FAKE_CALLER_ACCOUNT:-123456789012}"
    ;;
  lambda/get-event-source-mapping)
    if [[ -f "${FAKE_STATE_DIR:?}/mapping-disabled" ]]; then
      printf '%s\n' "Disabled"
    else
      printf '%s\n' "Enabled"
    fi
    ;;
  lambda/update-event-source-mapping)
    touch "${FAKE_STATE_DIR:?}/mapping-disabled"
    printf '%s\n' '{}'
    ;;
  events/describe-rule)
    bus="$(argument_value --event-bus-name "$@")"
    name="$(argument_value --name "$@")"
    if [[ -f "${FAKE_STATE_DIR:?}/rule-${bus}-${name}-disabled" ]]; then
      printf '%s\n' "DISABLED"
    else
      printf '%s\n' "ENABLED"
    fi
    ;;
  events/disable-rule)
    bus="$(argument_value --event-bus-name "$@")"
    name="$(argument_value --name "$@")"
    touch "${FAKE_STATE_DIR:?}/rule-${bus}-${name}-disabled"
    ;;
  *)
    exit 93
    ;;
esac
EOF

chmod +x "${FAKE_BIN}/aws" "${FAKE_BIN}/terraform" "${PAUSE_SCRIPT}"
export AWS_CALLS TF_CALLS
export FAKE_STATE_DIR="${WORK_DIR}"
export PATH="${FAKE_BIN}:${PATH}"
export PORTSCANNER_EXPECTED_AWS_ACCOUNT_ID="123456789012"
export PORTSCANNER_EXPECTED_AWS_REGION="us-east-2"

"${PAUSE_SCRIPT}" "${TF_ROOT}" >"${WORK_DIR}/first-output"
"${PAUSE_SCRIPT}" "${TF_ROOT}" >"${WORK_DIR}/second-output"

[[ "$(rg -c 'lambda update-event-source-mapping' "${AWS_CALLS}")" == "1" ]] ||
  fail "event-source mapping disable must be idempotent"
[[ "$(rg -c 'events disable-rule' "${AWS_CALLS}")" == "2" ]] ||
  fail "EventBridge disable must be idempotent"
rg -q 'events disable-rule .*--event-bus-name portscanner-bus' "${AWS_CALLS}" ||
  fail "custom EventBridge bus was not passed to the emergency pause"
if rg -q ' plan( |$)' "${TF_CALLS}"; then
  fail "emergency pause must not run terraform plan"
fi
rg -q 'Emergency dispatch pause verified' "${WORK_DIR}/first-output" ||
  fail "emergency pause did not report verification"

if FAKE_STATE_ACCOUNT="222222222222" "${PAUSE_SCRIPT}" "${TF_ROOT}" >"${WORK_DIR}/mismatch-output" 2>&1; then
  fail "Terraform-state account mismatch should fail"
fi
rg -q 'Terraform state account mismatch' "${WORK_DIR}/mismatch-output" ||
  fail "state-account mismatch was not explained"

echo "emergency pause tests passed"
