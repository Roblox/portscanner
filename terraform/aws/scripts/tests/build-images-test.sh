#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
BUILD_SCRIPT="${SCRIPT_DIR}/build-images.sh"
TF_ROOT="${AWS_DIR}/examples/created-vpc"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-build-images-test.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM
FAKE_BIN="${WORK_DIR}/bin"
mkdir -p "${FAKE_BIN}"

cat >"${FAKE_BIN}/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output_name="${!#}"
case "${output_name}" in
  repository_urls)
    if [[ "${FAKE_TF_MODE:-valid}" == "missing" ]]; then
      printf '%s\n' '{"inventory":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/inventory"}'
    else
      printf '%s\n' '{
        "inventory":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/inventory",
        "generator":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/generator",
        "parser":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/parser",
        "processor":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/processor",
        "migrator":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/migrator",
        "operator":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/operator",
        "scanner":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test/scanner"
      }'
    fi
    ;;
  deployment_state)
    printf '%s\n' '{
      "runtime_created":false,
      "migration_run":false,
      "operator_installed":false,
      "dispatch_enabled":false
    }'
    ;;
  *)
    echo "unexpected terraform invocation" >&2
    exit 90
    ;;
esac
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws invoked\n' >>"${AWS_MARKER:?}"
exit 91
EOF

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "buildx" && "${2:-}" == "version" ]]; then
  exit 0
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "build" && "${3:-}" == "--help" ]]; then
  printf '%s\n' '      --provenance string'
  printf '%s\n' '      --sbom string'
  exit 0
fi
echo "unexpected docker invocation" >&2
exit 92
EOF

chmod +x "${FAKE_BIN}/terraform" "${FAKE_BIN}/aws" "${FAKE_BIN}/docker"
export AWS_MARKER="${WORK_DIR}/aws-marker"

STDOUT_FILE="${WORK_DIR}/stdout"
STDERR_FILE="${WORK_DIR}/stderr"
if ! PATH="${FAKE_BIN}:${PATH}" \
  PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  <"${STDERR_FILE}" tee /dev/stderr >/dev/null
  fail "valid dry run failed"
fi

[[ ! -s "${STDOUT_FILE}" ]] || fail "dry run wrote digest input to stdout"
[[ ! -e "${AWS_MARKER}" ]] || fail "dry run invoked AWS"
DRY_RUN_LOG="$(<"${STDERR_FILE}")"
[[ "${DRY_RUN_LOG}" == *"architecture mapping: arm64 -> linux/arm64"* ]] ||
  fail "dry run omitted architecture mapping"
for component in inventory generator parser processor migrator operator scanner; do
  [[ "${DRY_RUN_LOG}" == *"${component}: context="* ]] ||
    fail "dry run omitted ${component} mapping"
done
[[ "${DRY_RUN_LOG}" == *"no AWS identity call, registry login, build, push, or digest output"* ]] ||
  fail "dry run did not state its side-effect boundary"

PATH="${FAKE_BIN}:${PATH}" \
  PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" x86_64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"
[[ ! -s "${STDOUT_FILE}" ]] || fail "x86 dry run wrote digest input to stdout"
X86_DRY_RUN_LOG="$(<"${STDERR_FILE}")"
[[ "${X86_DRY_RUN_LOG}" == *"architecture mapping: x86_64 -> linux/amd64"* ]] ||
  fail "x86 dry run omitted architecture mapping"

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run /tmp arm64 >/dev/null 2>&1; then
  fail "root outside terraform/aws was accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}/../created-vpc" arm64 >/dev/null 2>&1; then
  fail "root containing a traversal segment was accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" arm64 latest >/dev/null 2>&1; then
  fail "latest tag was accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" arm64 'unsafe;tag' >/dev/null 2>&1; then
  fail "unsafe tag was accepted"
fi

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true FAKE_TF_MODE=missing \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" arm64 >/dev/null 2>&1; then
  fail "incomplete foundation repository output was accepted"
fi

echo "build-images dry-run safety tests passed"
