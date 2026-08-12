#!/usr/bin/env bash
set -euo pipefail

POSTGRES_IMAGE="postgres:16.14-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
CONTAINER_NAME="portscanner-postgresql-test-$$"
DATABASE_NAME="portscanner"
DATABASE_PASSWORD="local-integration-only"

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for PostgreSQL integration tests" >&2
  exit 1
}
command -v uv >/dev/null 2>&1 || {
  echo "uv is required for PostgreSQL integration tests" >&2
  exit 1
}

cleanup() {
  docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
handle_signal() {
  exit 130
}
trap cleanup EXIT
trap handle_signal HUP INT TERM

docker run \
  --detach \
  --rm \
  --name "${CONTAINER_NAME}" \
  --env "POSTGRES_DB=${DATABASE_NAME}" \
  --env "POSTGRES_PASSWORD=${DATABASE_PASSWORD}" \
  --publish "127.0.0.1::5432" \
  "${POSTGRES_IMAGE}" \
  >/dev/null

ready=false
for _ in {1..60}; do
  if docker exec "${CONTAINER_NAME}" \
    pg_isready --username postgres --dbname "${DATABASE_NAME}" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done

if [[ "${ready}" != "true" ]]; then
  docker logs "${CONTAINER_NAME}" >&2
  echo "PostgreSQL did not become ready within 60 seconds" >&2
  exit 1
fi

host_port="$(
  docker inspect \
    --format='{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' \
    "${CONTAINER_NAME}"
)"
export TEST_DATABASE_URL="postgresql://postgres:${DATABASE_PASSWORD}@127.0.0.1:${host_port}/${DATABASE_NAME}"

# Run separately because both component suites intentionally use the same test module name.
uv run --all-packages pytest db/migrator/tests/test_postgresql_integration.py
uv run --all-packages pytest parser/tests/test_postgresql_integration.py
