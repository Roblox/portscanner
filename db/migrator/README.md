<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# ACT database migrator

The migrator applies paired PostgreSQL migrations under a database-scoped session
advisory lock. Application credential repair uses the same lock from secret read through
role grants and secret publication.

Lambda and CLI invocations require the expected `migration_checksum` (or
`--migration-checksum`). The migrator recomputes the ordered, length-prefixed artifact
hash before connecting to PostgreSQL and rejects mismatches or symlinked migration
files.

An `up` invocation targeted below migration `000004` applies the requested schema prefix
but deliberately skips application credential provisioning because the earlier object
grants do not guarantee database `CONNECT`. Lambda responses report
`credentials_status: "skipped_target_before_application_connect"` and
`credentials_repaired: false` in that case. Full ups and targets at or above `000004`
repair credentials normally.
