# Copyright 2026 Roblox Corporation
# SPDX-License-Identifier: Apache-2.0

SHELL := /usr/bin/env bash

GO ?= go
KUBECTL ?= kubectl
HELM ?= helm
IMG ?= portscanner-operator:latest
LOCALBIN ?= $(CURDIR)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
CONTROLLER_GEN_VERSION ?= v0.21.0
SETUP_ENVTEST_VERSION ?= v0.24.1
ENVTEST_K8S_VERSION ?= 1.36.x

.PHONY: all
all: test build

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -o bin/manager ./cmd/manager

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test ./...

# envtest is opt-in: it downloads local control-plane binaries and never uses
# the caller's live cluster.
.PHONY: test-envtest
test-envtest:
	@ASSETS="$$($(GO) run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION) use -p path $(ENVTEST_K8S_VERSION))" && \
		KUBEBUILDER_ASSETS="$$ASSETS" $(GO) test -tags=envtest ./internal/controller/...

.PHONY: generate
generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths="./..."
	$(GO) fmt ./api/...

.PHONY: manifests
manifests: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) \
		rbac:roleName=portscanner-operator,headerFile=hack/boilerplate.yaml.txt \
		crd:headerFile=hack/boilerplate.yaml.txt \
		paths="./..." \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac
	$(CONTROLLER_GEN) \
		crd:headerFile=hack/boilerplate.yaml.txt \
		paths="./..." \
		output:crd:artifacts:config=chart/portscanner/crds

.PHONY: verify-manifests
verify-manifests:
	$(KUBECTL) kustomize config/default >/dev/null
	$(HELM) lint chart/portscanner
	$(HELM) template portscanner chart/portscanner \
		--namespace portscanner-system \
		--kube-version 1.36.0 >/dev/null

.PHONY: docker-build
docker-build:
	docker build --tag $(IMG) .

.PHONY: install
install:
	$(KUBECTL) apply -f config/crd/bases/scanning.portscanner.io_scanners.yaml

.PHONY: uninstall
uninstall:
	$(KUBECTL) delete -f config/crd/bases/scanning.portscanner.io_scanners.yaml --ignore-not-found

.PHONY: deploy
deploy:
	$(KUBECTL) apply -k config/default

.PHONY: undeploy
undeploy:
	$(KUBECTL) delete -k config/default --ignore-not-found

$(CONTROLLER_GEN):
	mkdir -p $(LOCALBIN)
	GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
