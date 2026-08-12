<!--
SPDX-FileCopyrightText: 2026 Portscanner contributors
SPDX-License-Identifier: MIT
-->

# Integrating findings

Portscanner publishes immutable finding JSON to S3 and sends standard S3 object-created
notifications to an external SQS queue. No in-stack consumer reads that queue. This is
the supported boundary for ticketing, SIEM, paging, data-lake, or custom workflow
integration.

The SQS message is a pointer, not the finding itself:

```text
SQS message
  -> S3 event notification
  -> findings/... JSON object
  -> Finding contract
```

## Discover the handoff

Central Terraform examples expose the values a consumer needs:

```bash
terraform -chdir="$TF_ROOT" output -raw external_finding_queue_url
terraform -chdir="$TF_ROOT" output -raw external_finding_queue_arn
terraform -chdir="$TF_ROOT" output -raw external_finding_bucket_name
terraform -chdir="$TF_ROOT" output -raw external_finding_bucket_arn
```

Manage the consumer identity outside this stack. Its identity policy normally needs:

- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`, and
  `sqs:GetQueueAttributes` on the exact finding queue ARN; and
- `s3:GetObject` and `s3:GetObjectVersion` on
  `<external_finding_bucket_arn>/findings/*`.

Do not grant list, write, or delete access unless the downstream design separately
requires and reviews it.

## Consume safely

For each message:

1. Long-poll SQS and keep the receipt handle private.
2. Parse the message body as an AWS S3 event notification. Ignore the one-time
   `s3:TestEvent` after verifying its source.
3. Require `eventSource == "aws:s3"`, the exact configured bucket, an
   `ObjectCreated` event, and a key beneath `findings/`.
4. URL-decode the object key with form semantics (`unquote_plus` in Python).
5. Fetch the exact object version when the notification includes a version ID.
6. Bound the accepted object size, hash the bytes, and compare the digest with the
   object's `payload-sha256` metadata.
7. Parse JSON and validate it with the shared semantic validator:

   ```python
   import json

   from portscanner_contracts import validate_finding

   finding = validate_finding(json.loads(object_bytes))
   ```

   `schemas/finding.schema.json` is the language-neutral structural contract. Schema
   validation alone does not replace the semantic checks implemented by
   `validate_finding`.
8. Commit the downstream side effect idempotently.
9. Delete the SQS message only after every referenced finding object in that message
   has been accepted or safely recorded.

On a transient failure, leave the message for retry and extend visibility when
processing may exceed the queue timeout. On malformed, unauthorized, or
contract-incompatible data, preserve diagnostics without logging sensitive payloads,
then allow the configured redrive policy to isolate the message.

S3 notifications and standard SQS delivery are at least once and are not globally
ordered. A notification can be duplicated, delayed, or delivered with other records.
Never use queue receive order as finding state order.

## Event and snapshot documents

`kind == "finding_event"` represents a lifecycle transition:

- `opened`;
- `reopened`;
- `updated`; or
- `resolved`.

Use `event.event_key` as the immutable idempotency key. Apply transitions according to
`event.occurred_at` and the finding's monotonic `version`, not queue order.

`kind == "current_finding"` is a periodic repair snapshot. It deliberately has no
`event` member. Upsert it by `finding.fingerprint` and `finding.version`; repeated
snapshots of the same state are expected and should not create duplicate tickets.

Both kinds use `schema_version == "1.0"`. Reject unknown major versions until the
consumer has explicitly added compatibility. A representative transition is available
at `examples/finding.json`.

## Minimal canary inspection

During an evaluation, inspect without deleting:

```bash
QUEUE_URL="$(
  terraform -chdir="$TF_ROOT" output -raw external_finding_queue_url
)"

aws sqs receive-message \
  --queue-url "$QUEUE_URL" \
  --wait-time-seconds 20 \
  --max-number-of-messages 1 \
  --attribute-names All \
  --message-attribute-names All
```

The result should contain an S3 notification whose bucket matches
`external_finding_bucket_name` and whose key starts with `findings/events/` or
`findings/current/`. Fetch and validate that object before calling the canary complete.
The command above intentionally leaves the message in the queue.

## Production handoff checklist

- Pin the consumer to a reviewed contract version and test the repository examples.
- Restrict IAM to the exact queue and finding prefix.
- Validate bucket, key, object version, metadata hash, JSON, and semantic contract.
- Make ticket/SIEM writes idempotent before deleting the message.
- Handle both transition events and current-state repair snapshots.
- Monitor queue age, receive count, DLQ depth, object-fetch failures, and contract
  rejection counts.
- Redrive only after the consumer defect or compatibility gap is fixed.
- Keep raw finding payloads out of broadly accessible logs.

To add a new cloud inventory source rather than a finding consumer, follow
[Adding inventory or signal sources](adding-sources.md).
