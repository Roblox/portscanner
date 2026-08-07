#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
AWS_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
EXPECTED_REPOSITORY_ROOT="$(CDPATH= cd -- "${AWS_DIR}/../.." && pwd -P)"

usage() {
  echo "usage: $0 [--dry-run] <central-terraform-root> <arm64|x86_64> [source-revision-or-tag]" >&2
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "$*" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

case "${PORTSCANNER_DRY_RUN:-false}" in
  true) DRY_RUN=true ;;
  false) DRY_RUN=false ;;
  *) die "PORTSCANNER_DRY_RUN must be true or false" ;;
esac

case "${PORTSCANNER_ALLOW_DIRTY:-false}" in
  true) ALLOW_DIRTY=true ;;
  false) ALLOW_DIRTY=false ;;
  *) die "PORTSCANNER_ALLOW_DIRTY must be true or false" ;;
esac

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  shift
fi

[[ $# -ge 2 && $# -le 3 ]] || usage

ROOT_ARG="$1"
ARCHITECTURE="$2"
SOURCE_ARGUMENT="${3:-}"

[[ "${ROOT_ARG}" =~ ^[A-Za-z0-9_./-]+$ ]] ||
  die "Terraform root contains unsupported characters"
case "/${ROOT_ARG}/" in
  *"/../"*) die "Terraform root must not contain '..' path segments" ;;
esac
[[ "${ROOT_ARG}" != -* ]] || die "Terraform root must not begin with '-'"

case "${ARCHITECTURE}" in
  arm64) PLATFORM="linux/arm64" ;;
  x86_64) PLATFORM="linux/amd64" ;;
  *) die "architecture must be arm64 or x86_64" ;;
esac

for required_command in git terraform aws docker jq python3 tar; do
  require_command "${required_command}"
done
docker buildx version >/dev/null 2>&1 || die "Docker buildx is required"

if [[ "${ROOT_ARG}" = /* ]]; then
  ROOT_CANDIDATE="${ROOT_ARG}"
else
  ROOT_CANDIDATE="$(pwd -P)/${ROOT_ARG}"
fi
[[ -d "${ROOT_CANDIDATE}" ]] || die "Terraform root does not exist: ${ROOT_ARG}"
ROOT="$(CDPATH= cd -- "${ROOT_CANDIDATE}" && pwd -P)"

case "${ROOT}" in
  "${AWS_DIR}/application" | \
    "${AWS_DIR}/examples/created-vpc" | \
    "${AWS_DIR}/examples/existing-vpc" | \
    "${AWS_DIR}/examples/multi-account-central")
    ;;
  "${AWS_DIR}/examples/member-account")
    die "member-account is not a central image deployment root"
    ;;
  *)
    die "Terraform root must be application, created-vpc, existing-vpc, or multi-account-central"
    ;;
esac
[[ -f "${ROOT}/main.tf" ]] || die "${ROOT} is not a Terraform root with main.tf"

REPOSITORY_ROOT="$(git -C "${EXPECTED_REPOSITORY_ROOT}" rev-parse --show-toplevel 2>/dev/null)" ||
  die "repository root could not be resolved"
REPOSITORY_ROOT="$(CDPATH= cd -- "${REPOSITORY_ROOT}" && pwd -P)"
[[ "${REPOSITORY_ROOT}" == "${EXPECTED_REPOSITORY_ROOT}" ]] ||
  die "script must run from the expected repository checkout"

HEAD_COMMIT="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" ||
  die "the checkout has no resolvable HEAD commit"
[[ "${HEAD_COMMIT}" =~ ^[0-9a-f]{40,64}$ ]] || die "HEAD is not a supported Git object ID"

if [[ -n "${SOURCE_ARGUMENT}" ]]; then
  [[ "${SOURCE_ARGUMENT}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,114}$ ]] ||
    die "source revision/tag must be Docker-safe and at most 115 characters"
  [[ "$(printf '%s' "${SOURCE_ARGUMENT}" | tr '[:upper:]' '[:lower:]')" != "latest" ]] ||
    die "the mutable latest tag is forbidden"
  SOURCE_COMMIT="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify "${SOURCE_ARGUMENT}^{commit}" 2>/dev/null)" ||
    die "source revision/tag does not resolve to a commit"
  [[ "${SOURCE_COMMIT}" == "${HEAD_COMMIT}" ]] ||
    die "source revision/tag must resolve to the checked-out HEAD"
  SOURCE_TAG_BASE="${SOURCE_ARGUMENT}"
else
  SOURCE_COMMIT="${HEAD_COMMIT}"
  SOURCE_TAG_BASE="${HEAD_COMMIT}"
fi
SOURCE_TAG="${SOURCE_TAG_BASE}-${ARCHITECTURE}"

WORKTREE_STATUS="$(git -C "${REPOSITORY_ROOT}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${WORKTREE_STATUS}" ]]; then
  [[ "${ALLOW_DIRTY}" == "true" ]] ||
    die "source checkout is not clean; review and commit it before publishing"
  [[ "${DRY_RUN}" == "true" ]] ||
    die "PORTSCANNER_ALLOW_DIRTY is permitted only with --dry-run"
  log "warning: dirty dry run; uncommitted files are excluded from build inputs"
fi

COMPONENTS=(
  inventory
  generator
  parser
  processor
  migrator
  operator
  scanner
)
DOCKERFILES=(
  inventory/Dockerfile
  generator/Dockerfile
  parser/Dockerfile
  processor/Dockerfile
  db/migrator/Dockerfile
  operator/Dockerfile
  scanner/nmap/Dockerfile
)
CONTEXTS=(
  .
  .
  .
  .
  .
  operator
  .
)

for index in "${!COMPONENTS[@]}"; do
  git -C "${REPOSITORY_ROOT}" cat-file -e "${SOURCE_COMMIT}:${DOCKERFILES[$index]}" ||
    die "Dockerfile is missing for ${COMPONENTS[$index]}"
  if [[ "${CONTEXTS[$index]}" == "." ]]; then
    git -C "${REPOSITORY_ROOT}" cat-file -e "${SOURCE_COMMIT}^{tree}" ||
      die "repository build context is missing"
  else
    git -C "${REPOSITORY_ROOT}" cat-file -e "${SOURCE_COMMIT}:${CONTEXTS[$index]}" ||
      die "build context is missing for ${COMPONENTS[$index]}"
  fi
done

if ! REPOSITORY_URLS_JSON="$(terraform "-chdir=${ROOT}" output -json repository_urls)"; then
  die "repository_urls output is unavailable; apply this central root first"
fi
if ! DEPLOYMENT_STATE_JSON="$(terraform "-chdir=${ROOT}" output -json deployment_state)"; then
  die "deployment_state output is unavailable; apply this central root first"
fi

EXPECTED_COMPONENTS_JSON='["generator","inventory","migrator","operator","parser","processor","scanner"]'
if ! jq -e --argjson expected "${EXPECTED_COMPONENTS_JSON}" \
  'type == "object" and keys == ($expected | sort) and all(.[]; type == "string")' \
  <<<"${REPOSITORY_URLS_JSON}" >/dev/null; then
  die "repository_urls must contain exactly the seven expected component repositories"
fi
if ! jq -e '
  type == "object"
  and keys == ["dispatch_enabled", "migration_run", "operator_installed", "runtime_created"]
  and all(.[]; type == "boolean")
  and ((.migration_run == false) or .runtime_created)
  and ((.operator_installed == false) or .migration_run)
  and ((.dispatch_enabled == false) or .operator_installed)
' <<<"${DEPLOYMENT_STATE_JSON}" >/dev/null; then
  die "deployment_state is malformed or violates staged deployment ordering"
fi
DEPLOYMENT_STAGE="$(jq -r '
  if .dispatch_enabled then "active"
  elif .operator_installed then "operator-installed"
  elif .migration_run then "migrated"
  elif .runtime_created then "runtime-paused"
  else "foundation"
  end
' <<<"${DEPLOYMENT_STATE_JSON}")"

REPOSITORY_URLS=()
REPOSITORY_NAMES=()
REPOSITORY_REGIONS=()
REPOSITORY_ACCOUNTS=()
REGISTRIES=()
REGISTRY_REGIONS=()
REGISTRY_COUNT=0

for component in "${COMPONENTS[@]}"; do
  REPOSITORY_URL="$(jq -er --arg component "${component}" '.[$component]' <<<"${REPOSITORY_URLS_JSON}")" ||
    die "repository URL is missing for ${component}"
  if [[ ! "${REPOSITORY_URL}" =~ ^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?/([a-z0-9][a-z0-9._/-]*)$ ]]; then
    die "repository URL for ${component} is not an exact ECR repository URL"
  fi

  REPOSITORY_ACCOUNT="${BASH_REMATCH[1]}"
  REPOSITORY_REGION="${BASH_REMATCH[2]}"
  REPOSITORY_NAME="${BASH_REMATCH[4]}"
  REGISTRY="${REPOSITORY_URL%%/*}"

  [[ "${REPOSITORY_REGION}" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] ||
    die "repository URL for ${component} has an invalid AWS region"
  [[ -n "${REPOSITORY_NAME}" && "${REPOSITORY_NAME}" != */ && "${REPOSITORY_NAME}" != *"//"* ]] ||
    die "repository URL for ${component} has an invalid repository name"

  REPOSITORY_URLS+=("${REPOSITORY_URL}")
  REPOSITORY_NAMES+=("${REPOSITORY_NAME}")
  REPOSITORY_REGIONS+=("${REPOSITORY_REGION}")
  REPOSITORY_ACCOUNTS+=("${REPOSITORY_ACCOUNT}")

  REGISTRY_SEEN=false
  if [[ "${REGISTRY_COUNT}" -gt 0 ]]; then
    for existing_registry in "${REGISTRIES[@]}"; do
      if [[ "${existing_registry}" == "${REGISTRY}" ]]; then
        REGISTRY_SEEN=true
        break
      fi
    done
  fi
  if [[ "${REGISTRY_SEEN}" == "false" ]]; then
    REGISTRIES+=("${REGISTRY}")
    REGISTRY_REGIONS+=("${REPOSITORY_REGION}")
    REGISTRY_COUNT=$((REGISTRY_COUNT + 1))
  fi
done

umask 077
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-images.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

SOURCE_TREE="${WORK_DIR}/source"
mkdir -p "${SOURCE_TREE}"
if ! git -C "${REPOSITORY_ROOT}" archive --format=tar "${SOURCE_COMMIT}" |
  tar -xf - -C "${SOURCE_TREE}"; then
  die "could not create a committed-only build context"
fi

MIGRATION_CHECKSUM="$(python3 - "${SOURCE_TREE}/db/migrations" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
if not root.is_dir():
    raise SystemExit(f"migration directory is missing: {root}")

entries = sorted(root.iterdir(), key=lambda path: path.name.encode("utf-8"))
symlinks = [path.name for path in entries if path.is_symlink()]
if symlinks:
    raise SystemExit(f"migration directory contains a symlink: {symlinks[0]}")
paths = [path for path in entries if path.is_file()]
if not paths:
    raise SystemExit("migration directory contains no regular files")

digest = hashlib.sha256()
for path in paths:
    name = path.name.encode("utf-8")
    data = path.read_bytes()
    digest.update(len(name).to_bytes(8, "big"))
    digest.update(name)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
print(digest.hexdigest())
PY
)"
[[ "${MIGRATION_CHECKSUM}" =~ ^[0-9a-f]{64}$ ]] ||
  die "migration checksum calculation did not produce a SHA-256 value"

if ! BUILDX_HELP="$(docker buildx build --help 2>&1)"; then
  die "Docker buildx build is unavailable"
fi
PROVENANCE_SUPPORTED=false
SBOM_SUPPORTED=false
if [[ "${BUILDX_HELP}" == *"--provenance"* ]]; then
  PROVENANCE_SUPPORTED=true
else
  log "warning: this buildx version does not advertise provenance support"
fi
if [[ "${BUILDX_HELP}" == *"--sbom"* ]]; then
  SBOM_SUPPORTED=true
else
  log "warning: this buildx version does not advertise SBOM support"
fi

log "validated central deployment outputs at ${ROOT} (${DEPLOYMENT_STAGE})"
log "source revision: ${SOURCE_COMMIT}"
log "immutable image tag: ${SOURCE_TAG}"
log "architecture mapping: ${ARCHITECTURE} -> ${PLATFORM}"
for index in "${!COMPONENTS[@]}"; do
  log "  ${COMPONENTS[$index]}: context=${CONTEXTS[$index]} dockerfile=${DOCKERFILES[$index]} image=${REPOSITORY_URLS[$index]}:${SOURCE_TAG}"
done
log "migration checksum: ${MIGRATION_CHECKSUM}"

if [[ "${DRY_RUN}" == "true" ]]; then
  log "dry run complete; no AWS identity call, registry login, build, push, or digest output was performed"
  exit 0
fi

TRIVY_NAME="${TRIVY:-trivy}"
TRIVY_BIN="$(command -v "${TRIVY_NAME}" || true)"
[[ -n "${TRIVY_BIN}" ]] ||
  die "Trivy is required to scan release digests before deployment output"

AWS_REGION_VALUE="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [[ -z "${AWS_REGION_VALUE}" ]]; then
  AWS_REGION_VALUE="$(aws configure get region 2>/dev/null || true)"
fi
[[ -n "${AWS_REGION_VALUE}" ]] || die "AWS region is not configured"
[[ "${AWS_REGION_VALUE}" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] ||
  die "configured AWS region is invalid"

if ! AWS_IDENTITY_JSON="$(aws sts get-caller-identity --region "${AWS_REGION_VALUE}" --output json)"; then
  die "AWS identity is unavailable"
fi
if ! AWS_ACCOUNT="$(jq -er '.Account | select(test("^[0-9]{12}$"))' <<<"${AWS_IDENTITY_JSON}")" ||
  ! AWS_IDENTITY_ARN="$(jq -er '.Arn | select(type == "string" and length > 0)' <<<"${AWS_IDENTITY_JSON}")"; then
  die "AWS identity response is incomplete"
fi

for index in "${!COMPONENTS[@]}"; do
  [[ "${REPOSITORY_REGIONS[$index]}" == "${AWS_REGION_VALUE}" ]] ||
    die "configured region ${AWS_REGION_VALUE} does not match ${COMPONENTS[$index]} repository region ${REPOSITORY_REGIONS[$index]}"
  [[ "${REPOSITORY_ACCOUNTS[$index]}" == "${AWS_ACCOUNT}" ]] ||
    die "AWS identity account does not own the ${COMPONENTS[$index]} repository"
done
log "using AWS identity ${AWS_IDENTITY_ARN} in ${AWS_REGION_VALUE}"

ACTIVE_DOCKER_HOST=""
if [[ -z "${DOCKER_HOST:-}" ]]; then
  ACTIVE_DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
fi

export DOCKER_CONFIG="${WORK_DIR}/docker-config"
mkdir -p "${DOCKER_CONFIG}"
printf '{}\n' >"${DOCKER_CONFIG}/config.json"
if [[ -n "${ACTIVE_DOCKER_HOST}" ]]; then
  export DOCKER_HOST="${ACTIVE_DOCKER_HOST}"
fi

for index in "${!REGISTRIES[@]}"; do
  log "authenticating to ${REGISTRIES[$index]}"
  if ! aws ecr get-login-password --region "${REGISTRY_REGIONS[$index]}" |
    docker login --username AWS --password-stdin "${REGISTRIES[$index]}" 1>&2; then
    die "ECR authentication failed for ${REGISTRIES[$index]}"
  fi
done

lookup_existing_ecr_digest() {
  local repository_name="$1"
  local image_tag="$2"
  local region="$3"
  local response
  local digest

  if ! response="$(aws ecr list-images \
    --region "${region}" \
    --repository-name "${repository_name}" \
    --filter tagStatus=TAGGED \
    --output json)"; then
    log "could not determine whether ${repository_name}:${image_tag} already exists"
    return 2
  fi

  if digest="$(jq -er --arg image_tag "${image_tag}" '
    select(
      (.imageIds | type) == "array" and
      ([.imageIds[] | select(.imageTag == $image_tag)] | length) == 1
    ) |
    [.imageIds[] | select(.imageTag == $image_tag)][0].imageDigest |
    select(type == "string" and test("^sha256:[0-9a-f]{64}$"))
  ' <<<"${response}")"; then
    printf '%s' "${digest}"
    return 0
  fi

  if jq -e --arg image_tag "${image_tag}" '
    (.imageIds | type) == "array" and
    ([.imageIds[] | select(.imageTag == $image_tag)] | length) == 0
  ' <<<"${response}" >/dev/null; then
    return 1
  fi

  log "ECR returned an unexpected lookup result for ${repository_name}:${image_tag}"
  return 2
}

resolve_ecr_digest() {
  local repository_name="$1"
  local image_tag="$2"
  local region="$3"
  local attempt
  local candidate

  for attempt in 1 2 3 4 5; do
    if candidate="$(aws ecr describe-images \
      --region "${region}" \
      --repository-name "${repository_name}" \
      --image-ids "imageTag=${image_tag}" \
      --query 'imageDetails[0].imageDigest' \
      --output text)"; then
      if [[ "${candidate}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf '%s' "${candidate}"
        return 0
      fi
    fi
    if [[ "${attempt}" -lt 5 ]]; then
      log "waiting for ECR digest visibility for ${repository_name}:${image_tag}"
      sleep "${attempt}"
    fi
  done
  return 1
}

DIGESTS=()
for index in "${!COMPONENTS[@]}"; do
  COMPONENT="${COMPONENTS[$index]}"
  METADATA_FILE="${WORK_DIR}/${COMPONENT}-metadata.json"
  IMAGE_REFERENCE="${REPOSITORY_URLS[$index]}:${SOURCE_TAG}"

  if ECR_DIGEST="$(lookup_existing_ecr_digest \
    "${REPOSITORY_NAMES[$index]}" \
    "${SOURCE_TAG}" \
    "${REPOSITORY_REGIONS[$index]}")"; then
    log "reusing existing immutable ${COMPONENT} digest ${ECR_DIGEST}"
  else
    LOOKUP_STATUS=$?
    if [[ "${LOOKUP_STATUS}" -ne 1 ]]; then
      die "could not safely inspect the immutable tag for ${COMPONENT}"
    fi

    BUILD_ARGS=(
      buildx build
      --pull
      --platform "${PLATFORM}"
      --file "${SOURCE_TREE}/${DOCKERFILES[$index]}"
      --tag "${IMAGE_REFERENCE}"
      --label "org.opencontainers.image.revision=${SOURCE_COMMIT}"
      --metadata-file "${METADATA_FILE}"
      --push
    )
    if [[ "${COMPONENT}" == "operator" || "${COMPONENT}" == "scanner" ]]; then
      [[ "${PROVENANCE_SUPPORTED}" == "false" ]] || BUILD_ARGS+=("--provenance=true")
      [[ "${SBOM_SUPPORTED}" == "false" ]] || BUILD_ARGS+=("--sbom=true")
    else
      # Lambda requires a single-architecture image manifest. Attached BuildKit
      # attestations turn a single-platform push into an OCI image index, which
      # Lambda can reject even though the payload has only one runtime platform.
      [[ "${PROVENANCE_SUPPORTED}" == "false" ]] || BUILD_ARGS+=("--provenance=false")
      [[ "${SBOM_SUPPORTED}" == "false" ]] || BUILD_ARGS+=("--sbom=false")
    fi
    BUILD_ARGS+=("${SOURCE_TREE}/${CONTEXTS[$index]}")

    log "building and pushing ${COMPONENT} for ${PLATFORM}"
    docker "${BUILD_ARGS[@]}" 1>&2

    METADATA_DIGEST="$(jq -r '."containerimage.digest" // empty' "${METADATA_FILE}")"
    if [[ -n "${METADATA_DIGEST}" && ! "${METADATA_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      die "build metadata returned an invalid digest for ${COMPONENT}"
    fi

    if ! ECR_DIGEST="$(resolve_ecr_digest \
      "${REPOSITORY_NAMES[$index]}" \
      "${SOURCE_TAG}" \
      "${REPOSITORY_REGIONS[$index]}")"; then
      die "could not resolve a valid ECR digest for ${COMPONENT}"
    fi
    if [[ -n "${METADATA_DIGEST}" && "${METADATA_DIGEST}" != "${ECR_DIGEST}" ]]; then
      die "build metadata and ECR disagree on the ${COMPONENT} digest"
    fi
  fi

  log "scanning immutable ${COMPONENT} digest ${ECR_DIGEST}"
  "${TRIVY_BIN}" image \
    --scanners vuln \
    --ignore-unfixed \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --no-progress \
    --platform "${PLATFORM}" \
    "${REPOSITORY_URLS[$index]}@${ECR_DIGEST}" 1>&2 ||
    die "vulnerability scan failed for ${COMPONENT}@${ECR_DIGEST}"

  DIGESTS+=("${ECR_DIGEST}")
  log "verified ${COMPONENT} digest ${ECR_DIGEST}"
done

log "all seven image digests were resolved; writing reviewed HCL input to stdout"
printf 'image_digests = {\n'
for index in "${!COMPONENTS[@]}"; do
  printf '  %-9s = "%s"\n' "${COMPONENTS[$index]}" "${DIGESTS[$index]}"
done
printf '}\n\n'
printf 'migration_checksum = "%s"\n' "${MIGRATION_CHECKSUM}"
