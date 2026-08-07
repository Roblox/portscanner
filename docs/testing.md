<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Testing

Tests must prove safety and failure semantics, not only the successful scan path. All
repository fixtures must be synthetic and use only RFC 5737/3849 addresses.

## Local publication checks

The sanitizer has no third-party Python dependency:

```bash
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
python3 tools/sanitize.py --working-tree
```

Run configured repository checks before opening a pull request:

```bash
pre-commit run --all-files
```

The default sanitizer scans Git-tracked files. `--working-tree` additionally includes
untracked, non-ignored files so a new document or fixture is checked before staging.

## Unit tests

Install the locked workspace and run the full local Python, contract, schema,
generated-file, and license suite:

```bash
make sync
make check
```

Run the Go operator independently:

```bash
make test-go
make vet-go
```

`make ci` additionally renders Kubernetes and runs every offline Terraform
validation root. `make containers` builds all seven local images; it is kept
separate because image builds and vulnerability scans are substantially slower.
The target is local-only: it does not log in or push.

Adapter tests must cover pagination, deterministic identity, monotonic generation,
duplicate and reordered input, complete and incomplete snapshots, removal rules,
metadata filtering, signal rereads, ownership verdicts, throttling, malformed payloads,
and idempotent retries.

Scheduler, worker, and parser tests must cover expired work, stale ownership, denied
scope, rate exhaustion, timeout, partial output, malformed evidence, declared coverage,
UNKNOWN preservation, duplicate results, and generation isolation.

## Contract and schema tests

Versioned contracts require:

- schema validity checks;
- one minimal and one representative synthetic fixture;
- rejection fixtures for unknown versions and malformed required fields;
- backward-compatibility tests for every supported reader/writer overlap;
- canonical serialization tests for deterministic identifiers; and
- boundary tests for field length, item count, address family, and timestamp ordering.

Examples should use addresses such as `192.0.2.10`, `198.51.100.20`, `203.0.113.30`, or
`2001:db8::10` and non-live identifiers such as `resource-synthetic-a`.

## Generated drift

When source types, CRDs, manifests, or templates change, run the repository's generation
targets and require a clean diff:

```bash
make check-generated
make -C operator generate manifests
git diff --exit-code
```

Run commands from the component directory documented by its Makefile. Generated output
must be reproducible and reviewed together with its source.

## Database migrations

Every migration is tested twice:

1. **Clean database:** apply all migrations from an empty supported database.
2. **Upgrade database:** restore the prior released schema with synthetic rows, apply
   new migrations, and run old/new reader compatibility checks.

Also test transaction rollback, repeated migration invocation, index/lock duration on a
representative synthetic volume, and forward recovery after a worker is interrupted.
Destructive contraction belongs to a later release.

## Terraform

CI runs:

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
tflint
```

Run init/validate for each root module. Validation uses no live account and must not
require a variable file. Plan tests, where present, use mocked or sandbox-only values and
assert that dispatch defaults off, allowlists default empty, public storage is blocked,
and existing Config/CloudTrail/VPC resources are not replaced in reference mode.

Never upload a plan containing live identifiers as a public CI artifact.

## Kubernetes and Helm

For every Kustomize root and Helm chart:

- build or template with synthetic values;
- run lint;
- validate rendered objects with kubeconform;
- reject missing namespaces, mutable images, privileged defaults, broad RBAC, mounted
  cloud keys, writable root filesystems without justification, and absent resource
  limits; and
- verify dispatch is disabled in default and example values.

Custom-resource schemas should be supplied to kubeconform where available. A narrowly
documented ignore for an unavailable custom schema must not hide built-in Kubernetes
validation failures.

## Containers

Build every Dockerfile from a clean context, then:

- run component tests before publishing;
- inspect the final user, entrypoint, capabilities, and included files;
- reject secrets and package-manager caches;
- scan the image with Trivy;
- publish only immutable digests from protected release automation; and
- exercise startup with dispatch disabled.

Check the AWS publication helper without AWS credentials, a registry login, or image
builds:

```bash
bash -n terraform/aws/scripts/build-images.sh
bash -n terraform/aws/scripts/tests/build-images-test.sh
terraform/aws/scripts/tests/build-images-test.sh
```

The lightweight test supplies synthetic Terraform outputs and fake AWS/Docker commands.
It verifies that dry run prints all seven component/platform mappings to stderr, leaves
stdout empty, never calls AWS, and rejects an outside root, `latest`, and incomplete
foundation outputs. If ShellCheck is installed, also run:

```bash
shellcheck \
  terraform/aws/scripts/build-images.sh \
  terraform/aws/scripts/tests/build-images-test.sh
```

Network integration tests must use an isolated, explicitly authorized target owned by
the test operator. Public CI never scans a live host.

## Integration tests

A local integration stack should test:

1. complete snapshot acceptance;
2. new/changed/known classification;
3. duplicate signal coalescing and current-state reread;
4. ownership `ACTIVE` dispatch;
5. stale/moved/inactive/UNKNOWN suppression;
6. result upload and parse;
7. Exposure update only for declared complete coverage;
8. Finding lifecycle;
9. replay idempotency; and
10. dead-letter and cleanup paths.

Use fake provider clients and a fake scanner by default. A cloud sandbox test is manual,
approval-protected, disabled unless configured, and must always run cleanup.

## CI map

- core CI: Python, Go, schemas, and generated drift;
- Terraform: formatting, offline initialization/validation, and TFLint;
- Kubernetes: Kustomize, Helm, and kubeconform;
- containers: clean builds and Trivy;
- CodeQL: supported source languages;
- supply chain: license/REUSE, gitleaks, pre-commit, and sanitizer; and
- AWS sandbox: manual OIDC workflow with environment approval and unconditional cleanup.
