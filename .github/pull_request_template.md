<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

## Summary

- What problem does this solve?
- What behavior or contract changes?

## Safety and data

- [ ] Dispatch remains deny-by-default.
- [ ] Account, CIDR, profile, rate, deadline, and ownership gates are preserved.
- [ ] Failed or incomplete work remains UNKNOWN.
- [ ] Metadata is allowlisted and logs are redacted.
- [ ] Examples use only RFC 5737/3849 addresses and synthetic identifiers.
- [ ] No live data, internal terms, personal data, cloud IDs, state, keys, or kubeconfigs are included.

Describe any authorization, ownership, scanner traffic, IAM, parsing, retention, or
idempotency impact:

## Migration and rollback

- Database/schema compatibility:
- Terraform/image/manifest activation order:
- Feature gates:
- Rollback and cleanup:

## Verification

- [ ] Unit tests
- [ ] Contract/schema tests
- [ ] Integration/failure/idempotency tests
- [ ] Generated drift
- [ ] Terraform/Kubernetes/container checks as applicable
- [ ] `python3 tools/sanitize.py --working-tree`
- [ ] Documentation updated

Commands and results:

## Source-adapter checklist

Complete this section when adding or changing a snapshot/signal source.

- [ ] Complete snapshots and removal semantics
- [ ] Stable Target identity and monotonic generation
- [ ] Signals-as-hints with current-state reread
- [ ] Immediate pre-dispatch ownership revalidation
- [ ] Metadata allowlist/redaction
- [ ] Central profile/priority/deadline policy
- [ ] IAM/Terraform registration
- [ ] Review checklist in `docs/adding-sources.md`

## Canary

Does this require a separately authorized, low-rate, approval-protected canary? If yes,
describe the private change record and success/stop conditions without including live
values.
