<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) after the initial
public version is tagged.

## [Unreleased]

### Added

- Public architecture and operating model using
  **DISCOVER → PRIORITIZE → VERIFY → ACT**.
- AWS deployment, configuration, operations, security, scanning safety, data handling,
  testing, cost, and multi-account documentation.
- Implementation contract and review checklist for new inventory snapshots and change
  signal sources.
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
- Publication sanitizer with a denylist policy and unit tests.
- CI definitions for source/schema tests, generated drift, Terraform, Kubernetes/Helm,
  containers, CodeQL, license/REUSE, secret scanning, publication sanitization, and a
  disabled manual AWS sandbox.
- Security, contribution, conduct, issue, pull request, dependency update, pre-commit,
  and secret-scanning policies.

### Security

- Dispatch is documented as deny-by-default with account/CIDR/profile/rate gates and
  immediate ownership revalidation.
- Incomplete inventory or scan evidence is explicitly preserved as UNKNOWN.

[Unreleased]: https://github.com/Roblox/portscanner/commits/main
