# State bootstrap

Apply this root once with ordinary AWS environment credentials; no profile is embedded:

```sh
terraform init
terraform apply \
  -var='aws_region=us-east-1' \
  -var='expected_deployment_account_id=REPLACE_WITH_12_DIGIT_ACCOUNT_ID'
terraform output backend_configuration
```

The AWS provider refuses credentials from any other account.

Store the output values in an out-of-band backend configuration file, add a unique `key` such as `environments/example-central.tfstate` for every root, and initialize with `terraform init -backend-config=...`. Do not put credentials in that file or reuse a key between roots.

The generated S3 bucket has public access blocked, bucket-owner-enforced ownership, TLS-only policy, encryption, versioning, and noncurrent-version retention. The DynamoDB lock table uses on-demand capacity, encryption, and PITR.

Destruction warning: both resources have `prevent_destroy`, and the bucket does not force-delete. Removing those controls risks losing the source of truth for every managed resource and must be a separately reviewed retirement operation. Retained versions and the lock table incur small ongoing costs.
