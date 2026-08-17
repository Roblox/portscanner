# syntax=docker/dockerfile:1.7
FROM python:3.14-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /var/task

COPY requirements-build.txt inventory/requirements-runtime.txt /opt/portscanner/
RUN python -m pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    --upgrade \
    --force-reinstall \
    --requirement /opt/portscanner/requirements-build.txt \
    --requirement /opt/portscanner/requirements-runtime.txt

COPY contracts /opt/build/contracts
COPY inventory /opt/build/inventory
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps \
    /opt/build/contracts \
    /opt/build/inventory \
    && rm -rf /opt/build
RUN python -m pip uninstall --yes hatchling setuptools trove-classifiers pathspec packaging pluggy

COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]
CMD ["portscanner_inventory.handlers.snapshot.lambda_handler"]
