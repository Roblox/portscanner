# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

UV ?= uv

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

.PHONY: \
	sync format format-check lint typecheck test test-contracts \
	generate check-generated licenses check test-go vet-go sanitize \
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

generate:
	$(UV) run --package portscanner-contracts python schemas/generate.py
	$(UV) run --package portscanner-contracts python examples/generate.py

check-generated: generate
	git diff --exit-code -- schemas/*.schema.json examples/*.json

licenses:
	$(UV) run reuse lint

check: format-check lint typecheck test check-generated licenses

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
	docker build --file inventory/Dockerfile --tag portscanner-inventory:test .
	docker build --file generator/Dockerfile --tag portscanner-generator:test .
	docker build --file parser/Dockerfile --tag portscanner-parser:test .
	docker build --file processor/Dockerfile --tag portscanner-processor:test .
	docker build --file db/migrator/Dockerfile --tag portscanner-migrator:test .
	docker build --file scanner/nmap/Dockerfile --tag portscanner-scanner:test .
	docker build --file operator/Dockerfile --tag portscanner-operator:test operator

ci: check test-go vet-go sanitize terraform-validate kubernetes-validate
