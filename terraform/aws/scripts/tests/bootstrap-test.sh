#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
BOOTSTRAP_SCRIPT="${SCRIPT_DIR}/bootstrap.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-bootstrap-test.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

FAKE_BIN="${WORK_DIR}/bin"
CONFIG_FILE="${WORK_DIR}/environment.auto.tfvars.json"
ARTIFACT_ROOT="${WORK_DIR}/artifacts"
TF_CALLS="${WORK_DIR}/terraform-calls"
AWS_CALLS="${WORK_DIR}/aws-calls"
DEPLOY_CALLS="${WORK_DIR}/deploy-calls"
BUILD_CALLS="${WORK_DIR}/build-calls"
mkdir -p "${FAKE_BIN}"
: >"${TF_CALLS}"
: >"${AWS_CALLS}"
: >"${DEPLOY_CALLS}"
: >"${BUILD_CALLS}"

ENVIRONMENT_NAME="test-eval"
ACCOUNT_ID="123456789012"
REGION="us-east-1"
ARTIFACT_DIR="${ARTIFACT_ROOT}/${ENVIRONMENT_NAME}/${ACCOUNT_ID}/${REGION}"
BOOTSTRAP_STATE="${ARTIFACT_DIR}/state-bootstrap.tfstate"
BACKEND_CONFIG="${ARTIFACT_DIR}/backend.hcl"
IMAGE_INPUTS="${ARTIFACT_DIR}/images.tfvars"
BACKEND_KEY="environments/${ENVIRONMENT_NAME}/${ACCOUNT_ID}/${REGION}/deployment.tfstate"

write_config() {
  local environment_name="${1:-${ENVIRONMENT_NAME}}"
  local installer_arn="arn:"
  installer_arn+="aws:iam::${ACCOUNT_ID}:role/test-installer"
  cat >"${CONFIG_FILE}" <<EOF
{
  "environment": {
    "name": "${environment_name}",
    "aws": {"account_id": "${ACCOUNT_ID}", "region": "${REGION}"},
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
      "disposable": true,
      "destroy_data_on_teardown": true,
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

cat >"${FAKE_BIN}/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${TF_CALLS:?}"
if [[ "${1:-}" == "version" && "${2:-}" == "-json" ]]; then
  printf '%s\n' '{"terraform_version":"1.7.4"}'
  exit 0
fi

root="${1#-chdir=}"
operation="${2:-}"
case "${operation}" in
  init)
    ;;
  plan)
    plan_file=""
    for argument in "$@"; do
      if [[ "${argument}" == -out=* ]]; then
        plan_file="${argument#-out=}"
      fi
    done
    [[ -n "${plan_file}" ]] || exit 91
    : >"${plan_file}"
    ;;
  show)
    printf '%s\n' "saved bootstrap plan"
    ;;
  apply)
    state_file=""
    backup_file=""
    for argument in "$@"; do
      case "${argument}" in
        -state=*) state_file="${argument#-state=}" ;;
        -backup=*) backup_file="${argument#-backup=}" ;;
      esac
    done
    [[ -n "${state_file}" ]] || exit 92
    if [[ -f "${state_file}" && -n "${backup_file}" ]]; then
      cp "${state_file}" "${backup_file}"
    fi
    printf '%s\n' '{"version":4}' >"${state_file}"
    ;;
  output)
    if [[ "${root}" == */state-bootstrap ]]; then
      state_file=""
      for argument in "$@"; do
        case "${argument}" in
          -state=*) state_file="${argument#-state=}" ;;
        esac
      done
      [[ -f "${state_file}" ]] || exit 93
      printf '{"bucket":"%s","dynamodb_table":"%s","encrypt":true,"region":"%s"}\n' \
        "${FAKE_STATE_BUCKET:-test-eval-state-tfstate-abc123}" \
        "${FAKE_LOCK_TABLE:-test-eval-state-terraform-locks}" \
        "${FAKE_STATE_REGION:-us-east-1}"
    else
      [[ "${3:-}" == "-json" && "${4:-}" == "deployment_state" ]] || exit 94
      printf '%s\n' '{"runtime_created":false,"migration_run":false,"operator_installed":false,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":false}'
    fi
    ;;
  *)
    echo "unexpected terraform invocation: $*" >&2
    exit 95
    ;;
esac
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${AWS_CALLS:?}"
case "${1:-}/${2:-}" in
  sts/get-caller-identity)
    identity_arn="arn:aws:iam::123456789012:role/test-installer"
    printf '{"Account":"%s","Arn":"%s","UserId":"test"}\n' \
      "${FAKE_AWS_ACCOUNT_ID:-123456789012}" \
      "${identity_arn}"
    ;;
  s3api/head-bucket)
    [[ "${FAKE_BUCKET_FAILURE:-false}" != "true" ]]
    ;;
  dynamodb/list-tables)
    if [[ "${FAKE_TABLE_EXISTS:-false}" == "true" ]]; then
      printf '%s\n' '["test-eval-state-terraform-locks"]'
    else
      printf '%s\n' '[]'
    fi
    ;;
  dynamodb/describe-table)
    default_table_arn="arn:aws:dynamodb:us-east-1:123456789012:table/test-eval-state-terraform-locks"
    printf '%s\n' "${FAKE_TABLE_ARN:-${default_table_arn}}"
    ;;
  *)
    exit 96
    ;;
esac
EOF

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "buildx" && "${2:-}" == "version" ]]
EOF

cat >"${FAKE_BIN}/trivy" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"${FAKE_BIN}/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-C" && "${2:-}" == "${EXPECTED_REPOSITORY_ROOT:?}" ]]
case "${3:-}/${4:-}" in
  rev-parse/--show-toplevel)
    printf '%s\n' "${EXPECTED_REPOSITORY_ROOT}"
    ;;
  rev-parse/--verify)
    [[ "${5:-}" == "HEAD^{commit}" ]] || exit 97
    printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ;;
  status/--porcelain=v1)
    [[ "${5:-}" == "--untracked-files=all" ]] || exit 97
    [[ "${FAKE_GIT_DIRTY:-false}" != "true" ]] || printf '%s\n' ' M changed-file'
    ;;
  *)
    exit 97
    ;;
esac
EOF

cat >"${FAKE_BIN}/fake-deploy" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DEPLOY_CALLS:?}"
[[ "$*" == "foundation" ]]
EOF

cat >"${FAKE_BIN}/fake-build-images" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${BUILD_CALLS:?}"
if [[ "${FAKE_BUILD_OUTPUT:-valid}" == "invalid" ]]; then
  printf '%s\n' 'invalid generated input'
  exit 0
fi
DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
cat <<OUTPUT
image_digests = {
  inventory = "${DIGEST}"
  generator = "${DIGEST}"
  parser    = "${DIGEST}"
  processor = "${DIGEST}"
  migrator  = "${DIGEST}"
  operator  = "${DIGEST}"
  scanner   = "${DIGEST}"
}

migration_checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
lambda_architecture = "arm64"
node_ami_type = "AL2023_ARM_64_STANDARD"
node_instance_types = ["t4g.medium"]
OUTPUT
EOF

chmod +x \
  "${FAKE_BIN}/terraform" \
  "${FAKE_BIN}/aws" \
  "${FAKE_BIN}/docker" \
  "${FAKE_BIN}/trivy" \
  "${FAKE_BIN}/git" \
  "${FAKE_BIN}/fake-deploy" \
  "${FAKE_BIN}/fake-build-images"

run_bootstrap() {
  local selected_artifact_root="${1:-${ARTIFACT_ROOT}}"
  PATH="${FAKE_BIN}:${PATH}" \
    TF_CALLS="${TF_CALLS}" \
    AWS_CALLS="${AWS_CALLS}" \
    DEPLOY_CALLS="${DEPLOY_CALLS}" \
    BUILD_CALLS="${BUILD_CALLS}" \
    EXPECTED_REPOSITORY_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../../.." && pwd -P)" \
    PORTSCANNER_CONFIG_FILE="${CONFIG_FILE}" \
    PORTSCANNER_ARTIFACT_ROOT="${selected_artifact_root}" \
    PORTSCANNER_DEPLOY_SCRIPT="${FAKE_BIN}/fake-deploy" \
    PORTSCANNER_BUILD_IMAGES_SCRIPT="${FAKE_BIN}/fake-build-images" \
    PORTSCANNER_AUTO_APPROVE=true \
    "${BOOTSTRAP_SCRIPT}"
}

write_config
run_bootstrap >"${WORK_DIR}/first-output" 2>"${WORK_DIR}/first-error" ||
  fail "valid first bootstrap failed"

for generated_file in "${BOOTSTRAP_STATE}" "${BACKEND_CONFIG}" "${IMAGE_INPUTS}"; do
  [[ -f "${generated_file}" ]] || fail "bootstrap did not generate ${generated_file}"
  GENERATED_MODE="$(stat -f '%Lp' "${generated_file}" 2>/dev/null || stat -c '%a' "${generated_file}")"
  [[ "${GENERATED_MODE}" == "600" ]] ||
    fail "generated file was not mode 0600: ${generated_file}"
done
BACKEND_CONTENT="$(<"${BACKEND_CONFIG}")"
[[ "${BACKEND_CONTENT}" == *"key            = \"${BACKEND_KEY}\""* ]] ||
  fail "backend key was not deterministically derived from environment/account/Region"
for credential_field in access_key secret_key token profile shared_credentials_file; do
  [[ "${BACKEND_CONTENT}" != *"${credential_field}"* ]] ||
    fail "backend configuration contains credential material"
done
[[ "$(<"${DEPLOY_CALLS}")" == "foundation" ]] ||
  fail "bootstrap did not apply the paused foundation through deploy.sh"
[[ "$(<"${BUILD_CALLS}")" == *"/terraform/aws/deployment arm64"* ]] ||
  fail "bootstrap did not invoke build-images for the canonical root and architecture"
TF_LOG="$(<"${TF_CALLS}")"
[[ "${TF_LOG}" == *"-chdir="*"/terraform/aws/deployment init -input=false -reconfigure -backend-config=${BACKEND_CONFIG}"* ]] ||
  fail "bootstrap did not reconfigure the canonical S3 backend"
[[ "${TF_LOG}" != *"-target"* ]] ||
  fail "bootstrap used a targeted Terraform operation"

FIRST_BACKEND_CONTENT="$(<"${BACKEND_CONFIG}")"
run_bootstrap >/dev/null 2>"${WORK_DIR}/resume-error" ||
  fail "resumable bootstrap failed"
[[ "$(<"${BACKEND_CONFIG}")" == "${FIRST_BACKEND_CONTENT}" ]] ||
  fail "resumable bootstrap rewrote backend identity"
[[ "$(<"${WORK_DIR}/resume-error")" == *"verified resumable state bootstrap"* ]] ||
  fail "resumable bootstrap did not report state verification"

rm "${BACKEND_CONFIG}"
run_bootstrap >/dev/null 2>&1 ||
  fail "bootstrap did not safely regenerate a missing backend file from verified bootstrap state"
[[ "$(<"${BACKEND_CONFIG}")" == "${FIRST_BACKEND_CONTENT}" ]] ||
  fail "regenerated backend file did not match the original identity"

printf '%s\n' 'key = "unsafe/../collision.tfstate"' >"${BACKEND_CONFIG}"
chmod 600 "${BACKEND_CONFIG}"
if run_bootstrap >/dev/null 2>"${WORK_DIR}/backend-collision-error"; then
  fail "bootstrap overwrote a colliding backend configuration"
fi
[[ "$(<"${BACKEND_CONFIG}")" == 'key = "unsafe/../collision.tfstate"' ]] ||
  fail "bootstrap modified a colliding backend configuration"
[[ "$(<"${WORK_DIR}/backend-collision-error")" == *"backend configuration collision"* ]] ||
  fail "backend collision failure was not explicit"
printf '%s' "${FIRST_BACKEND_CONTENT}" >"${BACKEND_CONFIG}"
chmod 600 "${BACKEND_CONFIG}"

if FAKE_LOCK_TABLE="other-environment-locks" run_bootstrap >/dev/null 2>"${WORK_DIR}/state-collision-error"; then
  fail "bootstrap accepted state from a colliding environment"
fi
[[ "$(<"${WORK_DIR}/state-collision-error")" == *"bootstrap state collision"* ]] ||
  fail "bootstrap state collision failure was not explicit"

AWS_CALL_COUNT_BEFORE="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
jq '.environment.credentials = {"access_key": "must-not-parse"}' \
  "${CONFIG_FILE}" >"${WORK_DIR}/invalid-config.json"
mv "${WORK_DIR}/invalid-config.json" "${CONFIG_FILE}"
if run_bootstrap >/dev/null 2>"${WORK_DIR}/config-error"; then
  fail "bootstrap accepted unknown credential fields in environment JSON"
fi
AWS_CALL_COUNT_AFTER="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
[[ "${AWS_CALL_COUNT_AFTER}" == "${AWS_CALL_COUNT_BEFORE}" ]] ||
  fail "bootstrap contacted AWS before rejecting malformed configuration"
[[ "$(<"${WORK_DIR}/config-error")" == *"environment keys are invalid"* ]] ||
  fail "configuration parsing failure was not explicit"

write_config
if FAKE_AWS_ACCOUNT_ID="222222222222" run_bootstrap >/dev/null 2>"${WORK_DIR}/identity-error"; then
  fail "bootstrap accepted an unexpected AWS identity"
fi
[[ "$(<"${WORK_DIR}/identity-error")" == *"AWS identity mismatch"* ]] ||
  fail "bootstrap identity mismatch was not explicit"

AWS_CALL_COUNT_BEFORE="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
if AWS_REGION="us-west-2" run_bootstrap >/dev/null 2>"${WORK_DIR}/region-error"; then
  fail "bootstrap accepted an AWS Region that conflicts with environment configuration"
fi
AWS_CALL_COUNT_AFTER="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
[[ "${AWS_CALL_COUNT_AFTER}" == "${AWS_CALL_COUNT_BEFORE}" ]] ||
  fail "bootstrap called STS before rejecting the configured Region mismatch"
[[ "$(<"${WORK_DIR}/region-error")" == *"AWS_REGION mismatch"* ]] ||
  fail "bootstrap Region mismatch was not explicit"

AWS_CALL_COUNT_BEFORE="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
if FAKE_GIT_DIRTY=true run_bootstrap >/dev/null 2>"${WORK_DIR}/dirty-error"; then
  fail "bootstrap accepted a dirty source checkout before image publication"
fi
AWS_CALL_COUNT_AFTER="$(wc -l <"${AWS_CALLS}" | tr -d ' ')"
[[ "${AWS_CALL_COUNT_AFTER}" == "${AWS_CALL_COUNT_BEFORE}" ]] ||
  fail "bootstrap contacted AWS before rejecting a dirty checkout"
[[ "$(<"${WORK_DIR}/dirty-error")" == *"source checkout is not clean"* ]] ||
  fail "dirty checkout failure was not explicit"

write_config "../unsafe"
if run_bootstrap >/dev/null 2>"${WORK_DIR}/unsafe-path-error"; then
  fail "bootstrap accepted an environment name that could escape artifact/backend paths"
fi
[[ "$(<"${WORK_DIR}/unsafe-path-error")" == *"environment.name must be"* ]] ||
  fail "unsafe environment path failure was not explicit"
write_config

ORPHAN_ARTIFACT_ROOT="${WORK_DIR}/orphan-artifacts"
ORPHAN_DIR="${ORPHAN_ARTIFACT_ROOT}/${ENVIRONMENT_NAME}/${ACCOUNT_ID}/${REGION}"
mkdir -p "${ORPHAN_DIR}"
printf '%s\n' 'orphan backend' >"${ORPHAN_DIR}/backend.hcl"
chmod 600 "${ORPHAN_DIR}/backend.hcl"
if run_bootstrap "${ORPHAN_ARTIFACT_ROOT}" >/dev/null 2>"${WORK_DIR}/orphan-error"; then
  fail "bootstrap accepted a backend file without local bootstrap state"
fi
[[ "$(<"${WORK_DIR}/orphan-error")" == *"backend configuration exists without its bootstrap state"* ]] ||
  fail "orphan backend collision failure was not explicit"

LOST_STATE_ARTIFACT_ROOT="${WORK_DIR}/lost-state-artifacts"
if FAKE_TABLE_EXISTS=true run_bootstrap "${LOST_STATE_ARTIFACT_ROOT}" \
  >/dev/null 2>"${WORK_DIR}/lost-state-error"; then
  fail "bootstrap accepted existing remote state resources without matching local bootstrap state"
fi
[[ "$(<"${WORK_DIR}/lost-state-error")" == *"lock table"*"already exists"* ]] ||
  fail "lost bootstrap-state collision failure was not explicit"

printf '%s' "${FIRST_BACKEND_CONTENT}" >"${BACKEND_CONFIG}"
chmod 600 "${BACKEND_CONFIG}"
ORIGINAL_IMAGES="$(<"${IMAGE_INPUTS}")"
if FAKE_BUILD_OUTPUT=invalid run_bootstrap >/dev/null 2>"${WORK_DIR}/invalid-images-error"; then
  fail "bootstrap accepted malformed generated image inputs"
fi
[[ "$(<"${IMAGE_INPUTS}")" == "${ORIGINAL_IMAGES}" ]] ||
  fail "failed image generation replaced the previous atomic image input"

echo "bootstrap helper tests passed"
