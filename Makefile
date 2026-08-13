# SPDX-FileCopyrightText: 2026 Roblox
# SPDX-License-Identifier: MIT

UV ?= uv
PYTHON ?= python3
HELM ?= helm
KUBECONFORM ?= kubeconform
PORTSCANNER_TEST_PYTHON ?= $(CURDIR)/.venv/bin/python

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
	test-postgresql test-packaging \
	generate generate-runtime-requirements check-generated lock-check \
	licenses check test-go test-go-envtest vet-go sanitize \
	secret-scan terraform-script-tests terraform-validate \
	kubernetes-validate containers ci

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

test-postgresql:
	./tools/test_postgresql.sh

test-packaging:
	bash ./tools/test_migrator_package.sh

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

check: lock-check format-check lint typecheck test test-packaging check-generated licenses

test-go:
	cd operator && PORTSCANNER_TEST_PYTHON="$(PORTSCANNER_TEST_PYTHON)" go test ./...

test-go-envtest:
	PORTSCANNER_TEST_PYTHON="$(PORTSCANNER_TEST_PYTHON)" $(MAKE) -C operator test-envtest

vet-go:
	cd operator && go vet ./...

sanitize:
	$(UV) run python tools/sanitize.py --working-tree

secret-scan:
	gitleaks dir --redact --config .gitleaks.toml .

terraform-script-tests:
	./terraform/aws/scripts/tests/bootstrap-test.sh
	./terraform/aws/scripts/tests/canary-helpers-test.sh
	./terraform/aws/scripts/tests/deploy-test.sh
	./terraform/aws/scripts/tests/emergency-pause-test.sh
	./terraform/aws/scripts/tests/build-images-test.sh

terraform-validate:
	./terraform/aws/scripts/validate.sh

kubernetes-validate:
	@set -eu; \
	work_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/portscanner-kubernetes.XXXXXX")"; \
	trap 'rm -rf "$$work_dir"' EXIT; \
	schema_dir="$$work_dir/schemas"; \
	$(UV) run --frozen --package portscanner-generator \
		python tools/export_crd_schemas.py \
		--output-directory "$$schema_dir" \
		$$(git ls-files 'operator/config/crd/bases/*.yaml'); \
	count=0; \
	for sample in $$(git ls-files 'operator/config/samples/*.yaml'); do \
		for version in 1.35.0 1.36.0; do \
			$(KUBECONFORM) -strict -summary \
				-kubernetes-version "$$version" \
				-schema-location default \
				-schema-location "$$schema_dir/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
				"$$sample"; \
		done; \
	done; \
	for chart in $$(git ls-files 'Chart.yaml' '**/Chart.yaml'); do \
		for version in 1.35.0 1.36.0; do \
			$(HELM) lint "$$(dirname "$$chart")" --kube-version "$$version" >/dev/null; \
			rendered="$$work_dir/helm-$$count-$$version.yaml"; \
			$(HELM) template portscanner-ci "$$(dirname "$$chart")" \
				--include-crds --kube-version "$$version" >"$$rendered"; \
			$(KUBECONFORM) -strict -summary -skip CustomResourceDefinition \
				-kubernetes-version "$$version" \
				-schema-location default \
				-schema-location "$$schema_dir/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
				"$$rendered"; \
		done; \
		count=$$((count + 1)); \
	done

containers:
	$(PYTHON) tools/build_tracked_image.py --dockerfile inventory/Dockerfile --tag portscanner-inventory:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile generator/Dockerfile --tag portscanner-generator:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile parser/Dockerfile --tag portscanner-parser:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile processor/Dockerfile --tag portscanner-processor:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile db/migrator/Dockerfile --tag portscanner-migrator:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile scanner/nmap/Dockerfile --tag portscanner-scanner:test
	$(PYTHON) tools/build_tracked_image.py --dockerfile operator/Dockerfile --tag portscanner-operator:test

ci: check test-postgresql test-go test-go-envtest vet-go sanitize terraform-script-tests terraform-validate kubernetes-validate
