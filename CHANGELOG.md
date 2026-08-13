<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-12

### Added

- Public architecture and operating model using
  **DISCOVER → PRIORITIZE → VERIFY → ACT**.
- Concise root and component guides for the AWS deployment, inventory sources,
  contracts, scanning, operations, safety, and finding integrations.
- Versioned TargetEvent, ScanResultEnvelope, and Finding contracts with generated JSON
  Schemas and synthetic examples.
- AWS Config and direct-EC2 inventory snapshots, CloudTrail/EventBridge signal
  resolution, generation fencing, transactional outbox, and dispatch-time ownership
  revalidation.
- Priority/coverage dispatch, a one-shot Kubernetes Scanner operator, and a hardened
  Nmap full/targeted TCP worker.
- Generation-safe PostgreSQL Exposure state, generic finding rules, immutable finding
  handoff, and checksum-locked migrations.
- Staged Terraform for single-account and optional hub/spoke AWS deployment, including
  private EKS/Aurora, secure queues and buckets, alarms, image publication, and paused
  activation gates.
- Guarded single-account evaluation with one environment file, resumable state/image
  bootstrap, a Terraform-managed one-port canary, fail-closed account/Region checks,
  conservative scanner tuning, restricted EKS API access, and automatic return to pause.
- Hard scanner-Pod quotas, per-destination serialization, generator-side CIDR
  enforcement, endpoint-mode public-egress checks, and an AWS-only emergency dispatch
  brake.
- Durable pending-outbox replay beyond DynamoDB Streams retention and DLQ quarantine
  for deterministic generator/parser/projector contract failures.
- Digest-pinned PostgreSQL migration/parser integration tests for local and core CI.
- Standalone migrator source/wheel distributions with the canonical migration SQL
  embedded and clean-install payload verification.
- Enforced Terraform contract tests, Go/Python boundary and envtest coverage, Kubernetes
  1.35/1.36 rendering, dual-architecture container builds, Lambda handler resolution,
  and operator startup smoke.
- Publication sanitizer with a denylist policy and unit tests.
- CI definitions for source/schema tests, generated drift, Terraform, Kubernetes/Helm,
  containers, CodeQL, license/REUSE, secret scanning, publication sanitization, and a
  disabled manual AWS sandbox.
- Security, contribution, conduct, issue, pull request, dependency update, pre-commit,
  and secret-scanning policies.
- Helm-only Kubernetes packaging, optional finding export, and a PostgreSQL-first
  default deployment boundary.

### Security

- Dispatch is deny-by-default with account/CIDR/profile gates, immediate ownership
  revalidation, bounded per-Job rates, a deployment-wide Pod quota, and
  per-destination serialization.
- Incomplete inventory or scan evidence is explicitly preserved as UNKNOWN.

[Unreleased]: https://github.com/Roblox/portscanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Roblox/portscanner/releases/tag/v1.0.0
