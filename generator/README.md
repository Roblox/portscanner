# portscanner-generator

`portscanner-generator` is a Python 3.12 AWS Lambda package that turns one
immutable `TargetEvent` object into at most one Kubernetes `Scanner` resource.
It validates the SQS/S3 source, checks event freshness, revalidates inventory
ownership immediately before dispatch, cancels older generations, and uses a
DynamoDB claim state machine for retry-safe idempotency.

## Required environment

- `TARGET_EVENT_BUCKET` (or `S3_BUCKET`)
- `TARGET_EVENT_PREFIX` (or `S3_PREFIX`)
- `IDEMPOTENCY_TABLE` (or `DYNAMODB_TABLE` / `DISPATCH_TABLE_NAME`)
- `INVENTORY_TABLE` (or `TARGET_TABLE_NAME`) when constructing the bundled
  inventory ownership validator
- `EKS_CLUSTER_NAME`
- `K8S_NAMESPACE`
- `AWS_REGION` (or `AWS_DEFAULT_REGION`)

`K8S_API_GROUP`, when set, must be `scanning.portscanner.io`.
`K8S_API_VERSION`, when set, must be `v1alpha1`.

The DynamoDB table partition key defaults to `dispatch_id` and can be changed with
`DYNAMODB_PARTITION_KEY`. Enable DynamoDB TTL on the `expires_at` attribute.

The runtime prefers the shared `portscanner_contracts.parse_target_event()`
entrypoint so the contract package owns the complete event union, including
removals. It falls back to `TargetEvent.model_validate()` (or `from_dict()`) for
older released packages and isolated tests. When a contract does not carry a
separate trace identifier, its opaque event ID is propagated as the trace ID.
The inventory boundary supports both `validate_event(event)` and
`revalidate(target, generation)`.

## Tests

From the repository root, install the locked workspace and run the package tests. They
use only in-memory fakes:

```sh
uv sync --frozen --all-packages --group dev
uv run --package portscanner-generator pytest generator/tests
```

Build the Lambda image from the repository root so the shared contract and
inventory packages are included:

```sh
docker build -f generator/Dockerfile .
```
