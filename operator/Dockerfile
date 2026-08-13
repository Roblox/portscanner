# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.5
ARG BUILDER_IMAGE=golang:${GO_VERSION}-bookworm@sha256:6c5605ab3a9a9fb3c4eafe5b3d63cdbf3881caf113262b67862547b54a9db599

FROM --platform=$BUILDPLATFORM ${BUILDER_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /workspace

COPY operator/go.mod operator/go.sum ./
RUN go mod download

COPY operator .
COPY LICENSES/Apache-2.0.txt /workspace/third-party-licenses/Apache-2.0.txt
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -buildvcs=false -trimpath -tags="netgo,osusergo" \
    -ldflags="-s -w" -o /out/manager ./cmd/manager

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/Roblox/portscanner" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder --chmod=0555 /out/manager /manager
COPY --from=builder /workspace/LICENSE /licenses/LICENSE
COPY --from=builder /workspace/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
COPY --from=builder /workspace/third-party-licenses/Apache-2.0.txt /licenses/Apache-2.0.txt
USER 65532:65532
ENTRYPOINT ["/manager"]
