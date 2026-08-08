<!--
Copyright 2026 Roblox Corporation
SPDX-License-Identifier: Apache-2.0
-->

# Portscanner Kubernetes Operator

This directory is the public, Apache-2.0-licensed Kubernetes operator boundary
for `github.com/Roblox/portscanner/operator`. It defines the
`scanning.portscanner.io/v1alpha1` `Scanner` API and creates one bounded
Kubernetes Job for each accepted Scanner resource.

The operator does not schedule recurring scans and does not store raw scan
evidence in Kubernetes status. Result transport is the scanner image's
responsibility.

The operator is only a Kubernetes controller. It does not poll the generator's
SQS queue, call AWS APIs, or require AWS Pod Identity. The external generator
authenticates to EKS and creates namespaced `Scanner` resources.

## Lifecycle

1. A namespaced Scanner describes exactly one target and one source event.
2. The generator uses `deadline` as the latest dispatch time. Once the Scanner
   exists, the controller treats that dispatch decision as complete and does
   not truncate execution at `deadline`.
3. It creates a deterministic, owner-referenced Job name. Reconciliation never
   creates a second concurrent Job for the same Scanner.
4. `notAfter` is the absolute execution cutoff and alone determines the Job
   active deadline. An already-created Job is not stopped at `deadline`.
5. Job success or failure is mirrored into lifecycle-only Scanner conditions,
   outcome, and timestamps.
6. `spec.cancel: true` or deletion removes an active Job. A status-protection
   finalizer prevents Job TTL cleanup from racing terminal status reporting.
7. A terminal Scanner is requeued until `ttlSecondsAfterFinished`, then deleted;
   owner deletion removes any remaining Job. A zero TTL deletes immediately.

`retryLimit` maps to `backoffLimit`; `ttlSecondsAfterFinished` applies to both
the Job TTL controller and terminal Scanner cleanup. One-shot execution fields
are immutable after creation; only `spec.cancel` may change.

## Scanner image contract

The configured scanner image receives these arguments:

- `--target=<address>`
- `--profile=fast-full-tcp|targeted-tcp|deep`
- `--tcp-ports=<normalized explicit coverage>`
- `--scan-mode=fast|targeted|deep`
- `--service-detection` for the `deep` profile

`fast-full-tcp` always uses `1-65535`. `targeted-tcp` requires ports or ranges.
`deep` uses supplied coverage or explicitly defaults to `1-65535`. Explicit
coverage is limited to 256 combined port/range terms at admission and 256
normalized terms at Job construction, matching the shared result envelope.

Correlation is carried in environment variables, not annotations:

- `PORTSCANNER_EVENT_ID`, `PORTSCANNER_DIRECTIVE_ID`,
  `PORTSCANNER_TRACE_ID`, `PORTSCANNER_REASON`
- `PORTSCANNER_TARGET_ID`, `PORTSCANNER_TARGET_PROVIDER`,
  `PORTSCANNER_TARGET_SCOPE_ID`, `PORTSCANNER_TARGET_LOCATION`,
  `PORTSCANNER_TARGET_RESOURCE_ID`, `PORTSCANNER_TARGET_PRIVATE_ADDRESS`,
  `PORTSCANNER_TARGET_GENERATION`
- `PORTSCANNER_RUN_ID` from the Job-name Pod label and
  `PORTSCANNER_ATTEMPT_ID` from the Pod UID through Downward API field refs
- `PORTSCANNER_IMAGE_VERSION`, equal to the configured digest-pinned image URI
- `PORTSCANNER_SOURCE_EVENT_AT`, `PORTSCANNER_SOURCE_OBSERVED_AT`
- `PORTSCANNER_DEADLINE_AT`, the latest dispatch time, and
  `PORTSCANNER_NOT_AFTER`, the absolute execution cutoff
- `PORTSCANNER_RESOURCE_NAME`, `PORTSCANNER_RESOURCE_NAMESPACE`
- `PORTSCANNER_RESULT_BUCKET`, `PORTSCANNER_RESULT_PREFIX`

The scanner image must be configured as
`<repository>@sha256:<64-lowercase-hex-characters>`. Mutable tags are rejected
before the controller starts. The image should write results to the configured
external destination and exit zero on success or non-zero on failure.

## Install

Build and deploy the Kustomize base:

```sh
make docker-build IMG=portscanner-operator:your-tag
# Set images and environment-specific arguments in a Kustomize overlay.
kubectl apply -k config/default
```

The base's `portscanner-system` namespace is an overridable Kustomize default;
the controller itself never assumes an operator or Scanner namespace. Scanner
Jobs are created in the Scanner resource's namespace.

Install with Helm:

```sh
helm install portscanner ./chart/portscanner \
  --namespace portscanner-system \
  --create-namespace \
  --set operator.image.repository=example/portscanner-operator \
  --set operator.image.digest=sha256:<operator-digest> \
  --set scanner.image.repository=example/scanner \
  --set scanner.image.digest=sha256:<scanner-digest> \
  --set scanner.result.bucket=<results-bucket> \
  --set scanner.result.prefix=scan-results \
  --set-string generator.rbac.group=portscanner:generator
```

The chart owns the CRD, operator RBAC and Deployment, scanner ServiceAccounts
and least-privilege RBAC, both PriorityClasses, and the release-namespace
generator Role/RoleBinding. That Role grants only CRUD access to
`scanning.portscanner.io/scanners`; its EKS group defaults to
`portscanner:generator` and is configurable with `generator.rbac.group`. Configure
`scanner.namespaces` when Scanner resources will live outside the Helm release
namespace. Those namespaces must already exist.

All images, ServiceAccount names, result destination values, PriorityClass
names, resource bounds, node selectors, tolerations, and operator settings are
configurable in `values.yaml`. No cloud account, registry, node type, or scan
namespace is embedded in controller code. The all-zero operator/scanner digests
and placeholder result bucket in the default values are render-only
placeholders and must be replaced before deployment.

## Security

Scanner Pods run non-root with RuntimeDefault seccomp, no privilege escalation,
a read-only root filesystem, all Linux capabilities dropped, no
automounted Kubernetes API token, and a bounded writable `/tmp` emptyDir. CPU,
memory, and ephemeral-storage requests and limits are mandatory controller
configuration. Jobs use `restartPolicy: Never`, one completion, and one
parallel Pod. The scanner uses non-root TCP connect scans and does not require
raw-socket access or Kubernetes privileged-container mode.

The default scanner Role intentionally has no rules. Add narrowly scoped rules
only if a chosen scanner implementation documents a Kubernetes API need.

## Development

Go 1.26 and controller-runtime v0.24 are used together with their compatible
Kubernetes v0.36 modules. The Helm chart and AWS deployment support Kubernetes
1.35 and 1.36, keeping client/server minor-version skew within the supported
window.

```sh
make generate manifests
make fmt vet test
make verify-manifests
```

Unit tests use controller-runtime's fake client and require no cluster.
The envtest suite is explicitly opt-in and uses downloaded local API server
binaries rather than a live cluster:

```sh
make test-envtest
```

The sample uses `192.0.2.25`, an RFC 5737 documentation-only address.
