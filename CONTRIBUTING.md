<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Contributing

Thank you for helping improve Portscanner. Changes should preserve authorization,
ownership, UNKNOWN, idempotency, and data-minimization invariants.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report
vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not a public
issue.

## Before starting

- Search existing issues and pull requests.
- Open a design issue before changing contracts, Target identity/generation,
  authorization, scan behavior, evidence semantics, migrations, or deployment topology.
- Do not test against a public or third-party host.
- Do not add production data, internal measurements, slide assets, names, account
  identifiers, cloud resource IDs, local paths, or company integration claims.

## Development setup

Use supported Python and Go versions from CI. Install project-specific dependencies only
from the component you are changing. Install pre-commit and enable it:

```bash
python3 -m pip install pre-commit
pre-commit install
```

Run the public-content checks:

```bash
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
python3 tools/sanitize.py --working-tree
pre-commit run --all-files
```

See [docs/testing.md](docs/testing.md) for component, schema, generated, Terraform,
Kubernetes, container, and integration checks.

## Design rules

- Keep **DISCOVER → PRIORITIZE → VERIFY → ACT** boundaries explicit.
- Snapshot-driven inventory is authoritative; event-driven signals are hints.
- Apply removals only after a complete snapshot.
- Use stable Target identity and monotonic generations.
- Revalidate ownership immediately before dispatch.
- Preserve periodic known-door reconciliation while priority work advances.
- Treat failed or incomplete work as UNKNOWN.
- Keep provider adapters independent of scanner and parser internals.
- Select typed named scan profiles; never pass source-controlled command fragments.
- Default dispatch off and account/CIDR allowlists empty.
- Minimize and redact provider metadata.

Read [docs/adding-sources.md](docs/adding-sources.md) before adding an inventory or signal
adapter.

## Fixtures and examples

Use only:

- `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24` for IPv4 documentation;
- `2001:db8::/32` for IPv6 documentation;
- the exact synthetic account fixture allowed by the sanitizer when an account-shaped
  value is required; and
- invented identifiers such as `resource-synthetic-a`.

Prefer placeholders such as `${ACCOUNT_ID}` over account-shaped values. Never copy a
cloud console export or real scanner result.

## Pull requests

Keep changes focused and explain why the change is needed. Complete the pull request
template, including:

- behavior and contract changes;
- safety and data impact;
- migration/rollback plan;
- tests and generated outputs;
- documentation updates; and
- whether a separately authorized canary is needed.

Generated files must be committed with their source changes and reproduce cleanly.
Database changes use expand/contract sequencing and must support a rolling upgrade.
Infrastructure changes default disabled and support staged activation.

All required checks must pass. Do not weaken sanitizer, gitleaks, CodeQL, IaC,
Kubernetes, image, license, or test checks merely to make a pull request green.

## Commit and review hygiene

- Write clear commits with one purpose.
- Do not commit build output, Terraform state/variables, plans with live values, keys,
  kubeconfigs, credentials, or large binary artifacts.
- Pin or lock dependencies using the component's existing mechanism.
- Request security-focused review for authorization, IAM, parsing, scanner arguments,
  source adapters, CI permissions, sanitizer exceptions, and evidence handling.
- Treat changes to allowlists or suppressions as security changes.

## Documentation

Describe current behavior and explicit exclusions. Do not publish unsupported latency,
scale, coverage, or cost claims. Examples must be runnable only with operator-supplied
authorized values and should default to no dispatch.
