# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

UV ?= uv
PYTHON ?= python3

BASE_PYTHON_PATHS := contracts examples schemas tools
OPTIONAL_PYTHON_COMPONENTS := \
	db/migrator \
	generator \
	inventory \
	parser \
	processor \
	scanner/nmap
PYTHON_PATHS := $(BASE_PYTHON_PATHS) $(foreach path,$(OPTIONAL_PYTHON_COMPONENTS),$(if $(wildcard $(path)/pyproject.toml),$(path)))
TEST_PATHS := $(foreach path,$(PYTHON_PATHS),$(wildcard $(path)/tests))
RUNTIME_REQUIREMENTS := \
	requirements-build.txt \
	db/migrator/requirements-runtime.txt \
	generator/requirements-runtime.txt \
	inventory/requirements-runtime.txt \
	parser/requirements-runtime.txt \
	processor/requirements-runtime.txt \
	scanner/nmap/requirements-runtime.txt

.PHONY: \
	sync format format-check lint typecheck test test-contracts \
	generate generate-runtime-requirements check-generated lock-check \
	licenses check test-go vet-go sanitize \
	secret-scan terraform-validate kubernetes-validate containers ci

sync:
	$(UV) sync --frozen --all-packages --group dev

format:
	$(UV) run --all-packages ruff format $(PYTHON_PATHS)
	$(UV) run --all-packages ruff check --fix $(PYTHON_PATHS)

format-check:
	$(UV) run --all-packages ruff format --check $(PYTHON_PATHS)

lint:
	$(UV) run --all-packages ruff check $(PYTHON_PATHS)

typecheck:
	$(UV) run --all-packages mypy

test:
	@set -e; \
	for path in $(TEST_PATHS); do \
		echo "==> pytest $$path"; \
		$(UV) run --all-packages pytest "$$path"; \
	done

test-contracts:
	$(UV) run --package portscanner-contracts pytest contracts/tests

generate: generate-runtime-requirements
	$(UV) run --frozen --package portscanner-contracts python schemas/generate.py
	$(UV) run --frozen --package portscanner-contracts python examples/generate.py

generate-runtime-requirements:
	$(UV) run --frozen python tools/export_runtime_requirements.py

check-generated: lock-check generate
	git diff --exit-code -- schemas/*.schema.json examples/*.json $(RUNTIME_REQUIREMENTS)

lock-check:
	$(UV) lock --check
	$(UV) run --frozen python tools/export_runtime_requirements.py --check

licenses:
	$(UV) run reuse lint

check: lock-check format-check lint typecheck test check-generated licenses

test-go:
	cd operator && go test ./...

vet-go:
	cd operator && go vet ./...

sanitize:
	$(UV) run python tools/sanitize.py --working-tree

secret-scan:
	gitleaks dir --redact --config .gitleaks.toml .

terraform-validate:
	./terraform/aws/scripts/validate.sh

kubernetes-validate:
	kubectl kustomize operator/config/default >/dev/null

containers:
	$(PYTHON) tools/build_tracked_image.py --dockerfile inventory/Dockerfile --tag portscanner-inventory:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile generator/Dockerfile --tag portscanner-generator:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile parser/Dockerfile --tag portscanner-parser:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile processor/Dockerfile --tag portscanner-processor:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile db/migrator/Dockerfile --tag portscanner-migrator:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile scanner/nmap/Dockerfile --tag portscanner-scanner:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile operator/Dockerfile --context operator --tag portscanner-operator:test

ci: check test-go vet-go sanitize terraform-validate kubernetes-validate
