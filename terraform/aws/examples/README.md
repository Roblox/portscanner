# Synthetic examples

These roots are validation templates, not account-specific configuration:

- `created-vpc` uses documentation network `192.0.2.0/24`.
- `existing-vpc` uses synthetic VPC/subnet IDs and demonstrates validation.
- `multi-account-central` uses documentation network `198.51.100.0/24` and member account `123456789012`.
- `member-account` uses only account `123456789012`, an exact synthetic role ARN, and a synthetic central bus ARN.

Dispatch is disabled everywhere. Replace every synthetic value, configure remote state, review costs, and run the foundation stage before any apply. The examples intentionally use low-volume defaults that are not resilient production settings.

The examples retain the default ARM64 pairing (`lambda_architecture = "arm64"`, `node_ami_type = "AL2023_ARM_64_STANDARD"`). Build all seven images for `linux/arm64`, or change both settings and all external image builds to x86_64. The `finding` queue is an external notification handoff; no example attaches an in-stack consumer.

Destroying an example can delete compute and database resources. S3/ECR retention and state safeguards may intentionally block destroy until data is reviewed and preserved.
