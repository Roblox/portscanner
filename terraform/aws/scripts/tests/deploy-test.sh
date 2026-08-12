#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy.sh"
TF_ROOT="${AWS_DIR}/examples/created-vpc"

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
      printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"canary_mode":false}'
    else
      printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":true,"automatic_inventory_enabled":false,"canary_mode":true}'
    fi
    ;;
  apply)
    [[ -f "${3:-}" ]] || exit 93
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

echo "deploy helper tests passed"
