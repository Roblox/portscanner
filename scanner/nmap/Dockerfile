# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
FROM ${PYTHON_BASE}

ARG DEBIAN_SNAPSHOT=20260807T000000Z
ARG NMAP_VERSION=7.93+dfsg1-1

RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get -o Acquire::Check-Valid-Until=false upgrade --yes; \
    apt-get -o Acquire::Check-Valid-Until=false install --no-install-recommends --yes \
      "nmap=${NMAP_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 65532 scanner; \
    useradd --system --uid 65532 --gid scanner --home-dir /nonexistent \
      --shell /usr/sbin/nologin scanner; \
    install -d -m 1777 /tmp

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

COPY requirements-build.txt scanner/nmap/requirements-runtime.txt /opt/portscanner/
RUN python -m pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --require-hashes \
    --upgrade \
    --force-reinstall \
    --requirement /opt/portscanner/requirements-build.txt \
    --requirement /opt/portscanner/requirements-runtime.txt

WORKDIR /opt/build
COPY contracts ./contracts
COPY scanner/nmap ./scanner
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps ./contracts ./scanner && \
    rm -rf /opt/build
RUN python -m pip uninstall --yes hatchling setuptools trove-classifiers pathspec packaging pluggy

COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

WORKDIR /opt/portscanner-scanner

USER 65532:65532
ENTRYPOINT ["portscanner-verify"]
