<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Data handling

Inventory and scan evidence can reveal attack-surface details even when no credential is
present. Treat all live deployment data as confidential operational security data.

## Data classes

### Source inventory

May include account and Region references, provider resource IDs, public addresses,
network relationships, labels, and ownership context. Adapters must normalize only
fields required for stable identity, authorization, prioritization, and revalidation.

### Work and audit records

Include Target identity, generation, source timestamps, profile, deadline, ownership
verdict, dispatch outcome, and trace identifiers. Keep enough to explain why a scan did
or did not occur without copying full provider payloads.

### Raw evidence

May include addresses, ports, banners, certificates, software versions, protocol
responses, and scanner diagnostics. Raw evidence is immutable and access-restricted.
Do not place it in logs, CI artifacts, issues, or public test fixtures.

### Normalized Exposure and Finding state

Contains reachability observations, declared coverage, confidence/outcome, policy
context, and lifecycle history. This data can be as sensitive as raw evidence.

## Metadata allowlist

Provider metadata is deny-by-default. Each adapter declares a versioned allowlist of
normalized keys. A reasonable initial set is:

- a non-personal environment classification;
- a service reference that contains no hostname or account identifier;
- an opaque owner reference intended for machine routing; and
- policy labels with documented bounded values.

Do not ingest arbitrary tags, descriptions, user data, names, email addresses, ticket
bodies, deployment payloads, secrets, or full provider API responses.

For each allowed field:

- cap key and value length;
- normalize encoding;
- reject control characters;
- define whether the value may enter logs or Findings;
- test known secret/PII forms; and
- document the retention purpose.

Redact rather than hash low-entropy identifiers. A hash of an account number, address,
or short name can often be reversed and can still permit unwanted correlation.

## Storage controls

- Encrypt queues, objects, databases, backups, and Terraform state.
- Use separate least-privilege read/write identities for source, scanner, parser,
  finding, migration, and backup paths.
- Prefer immutable object keys and versioning for raw evidence.
- Block public object access and require transport encryption.
- Keep database and administrative endpoints off the public Internet.
- Enable access logging with the same redaction policy.
- Test restoration into an isolated environment with dispatch disabled.

## Logging

Logs should use opaque Target and trace identifiers. Avoid:

- live account numbers and role/resource identifiers;
- IP addresses and CIDRs;
- provider payloads and tags;
- scanner command output, banners, or certificates;
- credentials, tokens, signed URLs, database strings, and request headers; and
- personal names, contact details, or local filesystem paths.

Use bounded error classes such as `source_throttled`, `ownership_stale`,
`evidence_incomplete`, and `result_schema_invalid`. Put detailed evidence in the
restricted evidence store.

## Retention and deletion

Define retention separately for:

- accepted and failed snapshots;
- signals and dead letters;
- work/lease audit records;
- raw evidence;
- normalized Exposures;
- Finding history;
- logs and metrics; and
- backups.

Retention should meet the investigation purpose without becoming indefinite by default.
Deletion must account for object versions, replicas, snapshots, dead-letter queues,
search indexes, and backups. A Target removal does not automatically prove that all
historical evidence should be deleted; follow the operator's approved policy.

## Public fixtures and documentation

Public repository content must use only:

- RFC 5737 IPv4 documentation ranges;
- RFC 3849 IPv6 documentation addresses;
- explicitly synthetic identifiers;
- generic account/role variables; and
- invented metadata that cannot identify a person or environment.

Do not copy production events, scanner output, dashboards, measurements, screenshots,
slide assets, names, local paths, state, variable files, keys, or kubeconfigs.

`tools/sanitize.py` checks tracked files by default and can include untracked working
tree files with `--working-tree`. Its policy rejects internal terms, live-looking cloud
identifiers, personal data, non-documentation public addresses, sensitive file types,
all binary files by default, and symlinks that escape the repository. An intentionally
distributable binary requires a security-reviewed allowlist entry containing both its
exact repository-relative path and lowercase SHA-256; there are currently no such
entries. A changed path or byte fails closed. Git-ignored local caches remain outside
working-tree path selection rather than being scanned or allowlisted. The sanitizer is
a release gate, not a substitute for review.

Narrow sanitizer exceptions are limited to legal notice files, the public project URL,
and explicitly listed synthetic fixture values. Changes to the policy or its exceptions
require security-focused review.

## Incident handling

If sensitive data reaches the repository:

1. stop publication and disable affected automation;
2. treat exposed credentials or signed material as compromised and rotate/revoke them;
3. use the hosting provider's private security process;
4. remove the data from the working tree and, when required, repository history;
5. invalidate caches and artifacts;
6. run both secret scanning and the publication sanitizer; and
7. document the control failure without reproducing the sensitive value.
