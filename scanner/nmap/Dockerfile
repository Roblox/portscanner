# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

ARG PYTHON_BASE=python:3.12.11-slim-bookworm
FROM ${PYTHON_BASE}

ARG DEBIAN_SNAPSHOT=20250630T000000Z
ARG NMAP_VERSION=7.93+dfsg1-1

RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install --no-install-recommends --yes "nmap=${NMAP_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 65532 scanner; \
    useradd --system --uid 65532 --gid scanner --home-dir /nonexistent \
      --shell /usr/sbin/nologin scanner; \
    install -d -m 1777 /tmp

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /opt/build
COPY contracts ./contracts
COPY scanner/nmap ./scanner
RUN python -m pip install --no-cache-dir ./contracts ./scanner && \
    rm -rf /opt/build

WORKDIR /opt/portscanner-scanner

USER 65532:65532
ENTRYPOINT ["portscanner-verify"]
