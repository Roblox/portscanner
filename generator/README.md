<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Portscanner generator

The generator is a Python 3.12 AWS Lambda that turns one immutable
`TargetEvent` into at most one namespaced Kubernetes `Scanner` resource. It is
an internal deployment component; users configure it through
[`terraform/aws`](../terraform/aws/README.md), not by invoking it directly.

## Dispatch boundary

For each SQS/S3 event pointer, the generator:

1. validates the configured bucket/prefix, object integrity, contract, and
   freshness;
2. rejects targets outside the authorized account and deny-before-allow CIDR
   policy;
3. acquires a DynamoDB idempotency claim and compares the current inventory
   generation;
4. rereads provider ownership and scan-relevant policy immediately before
   dispatch;
5. cancels superseded Scanner resources; and
6. creates one deterministic Scanner resource only while the target is
   `ACTIVE` and the dispatch deadline is still valid.

`STALE`, `MOVED`, `INACTIVE`, ambiguous, or out-of-scope targets do not scan.
Retries may repeat reads but cannot create a second effective dispatch.

The runtime receives exact bucket, table, EKS, namespace, account, Region, and
CIDR settings from Terraform. It uses the standard AWS credential chain and
EKS authentication; no kubeconfig or static cloud credential is embedded in
the image.

## Development

From the repository root:

```sh
uv run --package portscanner-generator pytest generator/tests
docker build --file generator/Dockerfile --tag portscanner-generator:local .
```

The repository root is the required image context because the generator
packages the shared contracts and inventory ownership adapter. Tests use
in-memory fakes and never contact a live cluster or target.
