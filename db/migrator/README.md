<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Portscanner database migrator

The migrator applies paired PostgreSQL migrations under a database-scoped
session advisory lock. The canonical AWS deployment invokes it before
installing the operator, while all scan dispatch is paused.

## Integrity and locking

Every Lambda or CLI invocation supplies an expected migration checksum. Before
connecting, the migrator recomputes the ordered, length-prefixed hash of the
complete `db/migrations` artifact set and rejects:

- a checksum mismatch;
- a missing up/down pair or version gap;
- an unrelated file, directory, or symlink; or
- a previously applied migration whose recorded checksum changed.

Schema changes and application credential repair share the same advisory lock.
The owner role creates or repairs a least-privilege runtime role, grants
database connectivity and object privileges, then publishes that credential
to Secrets Manager. Runtime components never receive the migration owner
credential.

The packaged `portscanner-migrator` wheel embeds the same SQL payload.
`MIGRATIONS_PATH` or `--migrations` may select a separately reviewed set, but
the checksum remains mandatory.

## Development

From the repository root:

```sh
uv run --package portscanner-migrator pytest db/migrator/tests
./tools/test_migrator_package.sh
./tools/test_postgresql.sh
```

The PostgreSQL test uses a disposable local container. Migration changes must
remain reversible, regenerate the deployment checksum through the image build
flow, and be applied only while dispatch is paused.
