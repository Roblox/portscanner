#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT_DIR="$(CDPATH= cd -- "${TEST_DIR}/.." && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
BUILD_SCRIPT="${SCRIPT_DIR}/build-images.sh"
TF_ROOT="${AWS_DIR}/examples/created-vpc"
APPLICATION_ROOT="${AWS_DIR}/application"
EXISTING_ROOT="${AWS_DIR}/examples/existing-vpc"
CENTRAL_ROOT="${AWS_DIR}/examples/multi-account-central"
MEMBER_ROOT="${AWS_DIR}/examples/member-account"

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
    case "${FAKE_TF_STATE:-foundation}" in
      foundation)
        printf '%s\n' '{
          "runtime_created":false,
          "migration_run":false,
          "operator_installed":false,
          "dispatch_enabled":false
        }'
        ;;
      active)
        printf '%s\n' '{
          "runtime_created":true,
          "migration_run":true,
          "operator_installed":true,
          "dispatch_enabled":true
        }'
        ;;
      invalid)
        printf '%s\n' '{
          "runtime_created":false,
          "migration_run":false,
          "operator_installed":false,
          "dispatch_enabled":true
        }'
        ;;
      *)
        exit 89
        ;;
    esac
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

for central_root in "${APPLICATION_ROOT}" "${EXISTING_ROOT}" "${CENTRAL_ROOT}"; do
  PATH="${FAKE_BIN}:${PATH}" \
    PORTSCANNER_ALLOW_DIRTY=true \
    "${BUILD_SCRIPT}" --dry-run "${central_root}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}" ||
    fail "accepted central root failed: ${central_root}"
done

PATH="${FAKE_BIN}:${PATH}" \
  PORTSCANNER_ALLOW_DIRTY=true \
  FAKE_TF_STATE=active \
  "${BUILD_SCRIPT}" --dry-run "${CENTRAL_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}" ||
  fail "active deployment upgrade dry run failed"
UPGRADE_LOG="$(<"${STDERR_FILE}")"
[[ "${UPGRADE_LOG}" == *"(active)"* ]] ||
  fail "upgrade dry run omitted active deployment state"

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
  "${BUILD_SCRIPT}" --dry-run "${MEMBER_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  fail "member-account root was accepted"
fi
MEMBER_ERROR="$(<"${STDERR_FILE}")"
[[ "${MEMBER_ERROR}" == *"member-account is not a central image deployment root"* ]] ||
  fail "member-account rejection was not explicit"

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

if PATH="${FAKE_BIN}:${PATH}" PORTSCANNER_ALLOW_DIRTY=true FAKE_TF_STATE=invalid \
  "${BUILD_SCRIPT}" --dry-run "${TF_ROOT}" arm64 >/dev/null 2>&1; then
  fail "invalid deployment-stage ordering was accepted"
fi

REAL_GIT_PATH="$(PATH=/usr/bin:/bin command -v git)"
cat >"${FAKE_BIN}/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

for argument in "$@"; do
  if [[ "${argument}" == "status" ]]; then
    exit 0
  fi
done
exec "${REAL_GIT_PATH:?}" "$@"
EOF

cat >"${FAKE_BIN}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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

case "${1:-}/${2:-}" in
  sts/get-caller-identity)
    printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:role/test-publisher","UserId":"test"}'
    ;;
  ecr/get-login-password)
    printf '%s\n' 'test-password'
    ;;
  ecr/list-images)
    repository="$(argument_value --repository-name "$@")"
    component="${repository##*/}"
    if [[ "${FAKE_LOOKUP_ERROR_COMPONENT:-}" == "${component}" ]]; then
      echo "simulated ECR authorization failure" >&2
      exit 47
    fi
    state=$'\n'
    [[ ! -f "${FAKE_ECR_STATE:?}" ]] || state+="$(<"${FAKE_ECR_STATE}")"
    state+=$'\n'
    if [[ "${state}" == *$'\n'"${component}"$'\n'* ]]; then
      if [[ "${FAKE_INVALID_COMPONENT:-}" == "${component}" ]]; then
        printf '{"imageIds":[{"imageDigest":"invalid","imageTag":"%s"}]}\n' "${FAKE_IMAGE_TAG:?}"
      else
        printf '{"imageIds":[{"imageDigest":"%s","imageTag":"%s"}]}\n' "${DIGEST}" "${FAKE_IMAGE_TAG:?}"
      fi
    else
      printf '%s\n' '{"imageIds":[]}'
    fi
    ;;
  ecr/describe-images)
    repository="$(argument_value --repository-name "$@")"
    component="${repository##*/}"
    state=$'\n'
    [[ ! -f "${FAKE_ECR_STATE:?}" ]] || state+="$(<"${FAKE_ECR_STATE}")"
    state+=$'\n'
    [[ "${state}" == *$'\n'"${component}"$'\n'* ]] || exit 44
    printf '%s\n' "${DIGEST}"
    ;;
  *)
    echo "unexpected aws invocation: $*" >&2
    exit 91
    ;;
esac
EOF

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

if [[ "${1:-}" == "buildx" && "${2:-}" == "version" ]]; then
  exit 0
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "build" && "${3:-}" == "--help" ]]; then
  printf '%s\n' '      --provenance string'
  printf '%s\n' '      --sbom string'
  exit 0
fi
if [[ "${1:-}" == "login" ]]; then
  read -r _password || true
  exit 0
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "build" ]]; then
  metadata_file=""
  image_tag=""
  shift 2
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --metadata-file)
        metadata_file="$2"
        shift 2
        ;;
      --tag)
        image_tag="$2"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  [[ -n "${metadata_file}" && -n "${image_tag}" ]] || exit 92
  component="${image_tag##*/}"
  component="${component%%:*}"
  printf '%s\n' "${component}" >>"${DOCKER_BUILD_MARKER:?}"
  printf '%s\n' "${component}" >>"${FAKE_ECR_STATE:?}"
  printf '{"containerimage.digest":"%s"}\n' "${DIGEST}" >"${metadata_file}"
  exit 0
fi

echo "unexpected docker invocation: $*" >&2
exit 92
EOF

cat >"${FAKE_BIN}/trivy" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "image" ]] || exit 93
[[ " $* " == *" --platform linux/arm64 "* ]] || exit 93
image="${!#}"
[[ "${image}" =~ @sha256:[0-9a-f]{64}$ ]] || exit 93
component="${image%@*}"
component="${component##*/}"
[[ "${FAKE_TRIVY_FAIL_COMPONENT:-}" != "${component}" ]] || exit 94
printf '%s\n' "${image}" >>"${TRIVY_SCAN_MARKER:?}"
EOF

chmod +x "${FAKE_BIN}/git" "${FAKE_BIN}/aws" "${FAKE_BIN}/docker" "${FAKE_BIN}/trivy"
export REAL_GIT_PATH
export FAKE_ECR_STATE="${WORK_DIR}/ecr-state"
export DOCKER_BUILD_MARKER="${WORK_DIR}/docker-builds"
export TRIVY_SCAN_MARKER="${WORK_DIR}/trivy-scans"
export FAKE_IMAGE_TAG="$("${REAL_GIT_PATH}" -C "${AWS_DIR}/../.." rev-parse HEAD)-arm64"
printf '%s\n' inventory generator >"${FAKE_ECR_STATE}"
: >"${DOCKER_BUILD_MARKER}"
: >"${TRIVY_SCAN_MARKER}"

if ! PATH="${FAKE_BIN}:${PATH}" \
  AWS_REGION=us-east-1 \
  DOCKER_HOST=unix:///test-docker.sock \
  "${BUILD_SCRIPT}" "${TF_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  <"${STDERR_FILE}" tee /dev/stderr >/dev/null
  fail "resumable publication failed"
fi

PUBLISH_LOG="$(<"${STDERR_FILE}")"
BUILD_LOG="$(<"${DOCKER_BUILD_MARKER}")"
[[ "${PUBLISH_LOG}" == *"reusing existing immutable inventory digest"* ]] ||
  fail "existing inventory image was not reused"
[[ "${PUBLISH_LOG}" == *"reusing existing immutable generator digest"* ]] ||
  fail "existing generator image was not reused"
[[ "${BUILD_LOG}" != *"inventory"* && "${BUILD_LOG}" != *"generator"* ]] ||
  fail "existing immutable images were rebuilt"
for component in parser processor migrator operator scanner; do
  [[ "${BUILD_LOG}" == *"${component}"* ]] ||
    fail "missing image was not built: ${component}"
done
PUBLISH_OUTPUT="$(<"${STDOUT_FILE}")"
for component in inventory generator parser processor migrator operator scanner; do
  [[ "${PUBLISH_OUTPUT}" == *"${component}"*"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"* ]] ||
    fail "digest output is missing resumed component: ${component}"
done
[[ "${PUBLISH_OUTPUT}" == *"migration_checksum = \""* ]] ||
  fail "resumed publication omitted migration checksum"
[[ "$(wc -l <"${TRIVY_SCAN_MARKER}" | tr -d ' ')" -eq 7 ]] ||
  fail "every reused and newly built digest was not vulnerability-scanned"

if PATH="${FAKE_BIN}:${PATH}" \
  AWS_REGION=us-east-1 \
  DOCKER_HOST=unix:///test-docker.sock \
  FAKE_TRIVY_FAIL_COMPONENT=inventory \
  "${BUILD_SCRIPT}" "${TF_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  fail "vulnerability scan failure was accepted"
fi
[[ ! -s "${STDOUT_FILE}" ]] ||
  fail "digest output was emitted after a vulnerability scan failure"

printf '%s\n' inventory >"${FAKE_ECR_STATE}"
: >"${DOCKER_BUILD_MARKER}"
if PATH="${FAKE_BIN}:${PATH}" \
  AWS_REGION=us-east-1 \
  DOCKER_HOST=unix:///test-docker.sock \
  FAKE_INVALID_COMPONENT=inventory \
  "${BUILD_SCRIPT}" "${TF_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  fail "invalid existing ECR digest was accepted"
fi
INVALID_DIGEST_LOG="$(<"${STDERR_FILE}")"
[[ "${INVALID_DIGEST_LOG}" == *"could not safely inspect the immutable tag for inventory"* ]] ||
  fail "invalid existing digest failure was not explicit"
[[ ! -s "${DOCKER_BUILD_MARKER}" ]] ||
  fail "publication built an image after an invalid existing digest"

printf '%s\n' inventory >"${FAKE_ECR_STATE}"
: >"${DOCKER_BUILD_MARKER}"
if PATH="${FAKE_BIN}:${PATH}" \
  AWS_REGION=us-east-1 \
  DOCKER_HOST=unix:///test-docker.sock \
  FAKE_LOOKUP_ERROR_COMPONENT=inventory \
  "${BUILD_SCRIPT}" "${TF_ROOT}" arm64 >"${STDOUT_FILE}" 2>"${STDERR_FILE}"; then
  fail "ECR lookup failure was treated as a missing image"
fi
LOOKUP_ERROR_LOG="$(<"${STDERR_FILE}")"
[[ "${LOOKUP_ERROR_LOG}" == *"could not safely inspect the immutable tag for inventory"* ]] ||
  fail "ECR lookup failure was not explicit"
[[ ! -s "${DOCKER_BUILD_MARKER}" ]] ||
  fail "publication built an image after an ECR lookup failure"

echo "build-images helper tests passed"
