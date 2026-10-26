# syntax=docker/dockerfile:1.7
FROM python:3.15-slim-bookworm@sha256:575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
WORKDIR /var/task

COPY requirements-build.txt db/migrator/requirements-runtime.txt /opt/portscanner/
RUN python -m pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    --upgrade \
    --force-reinstall \
    --requirement /opt/portscanner/requirements-build.txt \
    --requirement /opt/portscanner/requirements-runtime.txt

COPY db/migrator /tmp/portscanner-migrator
COPY db/migrations /tmp/portscanner-migrator/migrations
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps /tmp/portscanner-migrator \
    && rm -rf /tmp/portscanner-migrator
RUN python -m pip uninstall --yes hatchling setuptools trove-classifiers pathspec packaging pluggy

COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]
CMD ["act_migrator.handler.lambda_handler"]
