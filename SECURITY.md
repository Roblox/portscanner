<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Security policy

## Supported versions

Security fixes are provided for the latest 1.x release and the default branch.
Older release lines should be upgraded before reporting an issue.

## Report a vulnerability privately

Use [GitHub private vulnerability
reporting](https://github.com/Roblox/portscanner/security/advisories/new).

Do not open a public issue, discussion, or pull request for an unpatched vulnerability.
Do not include live account identifiers, addresses, scanner evidence, credentials,
personal data, internal hostnames, or production payloads in a report. Use minimal
synthetic reproduction data.

The private report should include:

- affected commit or release;
- affected component and deployment mode;
- prerequisites and impact;
- minimal reproduction steps;
- whether scanning authorization or data exposure is involved; and
- suggested mitigation, if known.

Maintainers will acknowledge the report through GitHub, investigate it, coordinate a
fix and disclosure as appropriate, and credit reporters who request credit.

## Scope

Examples of relevant issues include:

- bypass of account, CIDR, profile, rate, or ownership gates;
- command injection or Target expansion;
- stale/recycled-address scanning;
- incorrect UNKNOWN-to-closed transitions;
- cross-source data or authorization confusion;
- credential, inventory, evidence, or Finding disclosure;
- unsafe parser handling of scanner output;
- privilege escalation in IAM, Kubernetes, CI, or containers;
- idempotency failures that cause repeated scanning; and
- sanitizer or release-pipeline bypasses that expose sensitive data.

Configuration questions, feature requests, and ordinary bugs without security impact
belong in the public issue templates.

## Research and testing

Only test assets you own or are explicitly authorized to test. Follow provider policy,
use conservative rates, avoid privacy violations and service disruption, and stop if
you observe impact. This project does not authorize testing any third-party deployment
or public host.

Do not use a suspected vulnerability to access data beyond what is needed to
demonstrate impact, establish persistence, alter findings, or generate uncontrolled
network traffic.

## Secrets or sensitive data in Git history

Report the exposure privately. Revoke or rotate affected credentials immediately;
history rewriting alone is not remediation. Preserve a minimal audit record outside the
public repository, remove public artifacts/caches where possible, and run both gitleaks
and `tools/sanitize.py --working-tree` before republishing.
