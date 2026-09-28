# syntax=docker/dockerfile:1.7
FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /var/task

COPY requirements-build.txt processor/requirements-runtime.txt /opt/portscanner/
RUN python -m pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    --upgrade \
    --force-reinstall \
    --requirement /opt/portscanner/requirements-build.txt \
    --requirement /opt/portscanner/requirements-runtime.txt

COPY contracts /tmp/portscanner-contracts
COPY parser /tmp/portscanner-parser
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps \
    /tmp/portscanner-contracts \
    /tmp/portscanner-parser \
    && rm -rf /tmp/portscanner-contracts /tmp/portscanner-parser

COPY processor /tmp/portscanner-processor
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps /tmp/portscanner-processor \
    && rm -rf /tmp/portscanner-processor
RUN python -m pip uninstall --yes hatchling setuptools trove-classifiers pathspec packaging pluggy

COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]
CMD ["act_processor.handler.lambda_handler"]
