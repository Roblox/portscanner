terraform {
  required_version = "= 1.7.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.15.0"
    }
  }
}

variable "name_prefix" {
  description = "Portable prefix for member-account resources."
  type        = string
  default     = "portscanner-member"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.name_prefix))
    error_message = "name_prefix must be 2-24 lowercase alphanumeric or hyphen characters."
  }
}

variable "enable_config_recording" {
  description = "Create a secure local Config bucket, recorder, and delivery channel."
  type        = bool
  default     = false
}

variable "enable_config_aggregation_authorization" {
  description = "Authorize the exact central account and region to aggregate this account's Config data."
  type        = bool
  default     = false
}

variable "central_config_account_id" {
  description = "Central Config aggregator account ID."
  type        = string
  default     = null
}

variable "central_config_region" {
  description = "Central Config aggregator region."
  type        = string
  default     = null
}

variable "create_collector_role" {
  description = "Create a read-only EC2 inventory role for the exact central collector principal."
  type        = bool
  default     = false
}

variable "collector_role_name" {
  description = "Deterministic collector role name; use the same name in each directly collected member account."
  type        = string
  default     = null

  validation {
    condition = (
      var.collector_role_name == null ||
      can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.collector_role_name))
    )
    error_message = "collector_role_name must be null or a valid IAM role name."
  }
}

variable "central_collector_principal_arn" {
  description = "Optional snapshot-only central IAM role ARN retained for compatibility."
  type        = string
  default     = null
}

variable "central_collector_principal_arns" {
  description = "Exact central snapshot and signal IAM role ARNs trusted to assume the member collector role."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.central_collector_principal_arns :
      can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", arn))
    ])
    error_message = "central_collector_principal_arns must contain only IAM role ARNs."
  }
}

variable "collector_external_id" {
  description = "External ID required when the exact central collector assumes the member role."
  type        = string
  default     = null
  sensitive   = true
}

variable "enable_event_forwarding" {
  description = "Activate filtered EC2 hints in this provider region. Requires a created or explicitly referenced management CloudTrail."
  type        = bool
  default     = false
}

variable "cloudtrail_mode" {
  description = "create provisions a member management trail, existing references a member or organization trail, and disabled forbids active API-event forwarding."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["create", "existing", "disabled"], var.cloudtrail_mode)
    error_message = "cloudtrail_mode must be create, existing, or disabled."
  }
}

variable "existing_cloudtrail_arn" {
  description = "Existing member or organization multi-region management trail ARN when cloudtrail_mode is existing."
  type        = string
  default     = null

  validation {
    condition = (
      var.existing_cloudtrail_arn == null ||
      can(regex("^arn:[^:]+:cloudtrail:[^:]+:[0-9]{12}:trail/.+$", var.existing_cloudtrail_arn))
    )
    error_message = "existing_cloudtrail_arn must be null or a CloudTrail trail ARN."
  }
}

variable "cloudtrail_retention_days" {
  description = "Current-object retention for a member trail created by this module."
  type        = number
  default     = 365

  validation {
    condition     = var.cloudtrail_retention_days >= 1
    error_message = "cloudtrail_retention_days must be positive."
  }
}

variable "central_event_bus_arn" {
  description = "Exact central custom EventBridge bus ARN."
  type        = string
  default     = null
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  allowed_cloudtrail_events = [
    "AssociateAddress",
    "AssignPrivateIpAddresses",
    "AttachNetworkInterface",
    "AuthorizeSecurityGroupIngress",
    "CreateNetworkInterface",
    "DeleteNetworkInterface",
    "DetachNetworkInterface",
    "DisassociateAddress",
    "ModifyInstanceAttribute",
    "ModifyNetworkInterfaceAttribute",
    "ModifySecurityGroupRules",
    "RebootInstances",
    "ReleaseAddress",
    "RevokeSecurityGroupIngress",
    "RunInstances",
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
    "UnassignPrivateIpAddresses"
  ]
  event_patterns = {
    cloudtrail = {
      source        = ["aws.ec2"]
      "detail-type" = ["AWS API Call via CloudTrail"]
      detail = {
        eventSource = ["ec2.amazonaws.com"]
        eventName   = local.allowed_cloudtrail_events
      }
    }
    state = {
      source        = ["aws.ec2"]
      "detail-type" = ["EC2 Instance State-change Notification"]
    }
  }
  rule_names = {
    cloudtrail = "${var.name_prefix}-ec2-write-forward"
    state      = "${var.name_prefix}-ec2-state-forward"
  }
  collector_principal_arns = setunion(
    var.central_collector_principal_arns,
    var.central_collector_principal_arn == null ? toset([]) : toset([
      var.central_collector_principal_arn
    ])
  )
  config_source_arn      = "arn:${data.aws_partition.current.partition}:config:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"
  cloudtrail_name        = "${var.name_prefix}-management"
  created_cloudtrail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}"
  effective_cloudtrail_arn = (
    var.cloudtrail_mode == "create" ? local.created_cloudtrail_arn :
    var.cloudtrail_mode == "existing" ? var.existing_cloudtrail_arn :
    null
  )
}

resource "terraform_data" "member_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition = !var.enable_config_aggregation_authorization ? true : try(
        can(regex("^[0-9]{12}$", var.central_config_account_id)) &&
        length(var.central_config_region) > 0,
        false
      )
      error_message = "Config aggregation authorization requires a 12-digit central account ID and central region."
    }

    precondition {
      condition = !var.create_collector_role ? true : try(
        length(local.collector_principal_arns) > 0 &&
        alltrue([
          for arn in local.collector_principal_arns :
          can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", arn))
        ]) &&
        length(var.collector_external_id) >= 16,
        false
      )
      error_message = "Collector role creation requires exact central IAM role ARNs and an external ID of at least 16 characters."
    }

    precondition {
      condition = !var.enable_event_forwarding || (
        var.central_event_bus_arn != null &&
        can(regex("^arn:[^:]+:events:[^:]+:[0-9]{12}:event-bus/.+$", var.central_event_bus_arn)) &&
        var.cloudtrail_mode != "disabled"
      )
      error_message = "Event forwarding requires an exact central custom event bus ARN and cloudtrail_mode create or existing."
    }

    precondition {
      condition = (
        var.cloudtrail_mode == "existing" &&
        var.existing_cloudtrail_arn != null
        ) || (
        var.cloudtrail_mode != "existing" &&
        var.existing_cloudtrail_arn == null
      )
      error_message = "existing_cloudtrail_arn is required only when cloudtrail_mode is existing."
    }
  }
}

resource "aws_s3_bucket" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket_prefix = substr("${var.name_prefix}-config-", 0, 37)
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    id     = "config-retention"
    status = "Enabled"
    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.config]
}

data "aws_iam_policy_document" "config_bucket" {
  count = var.enable_config_recording ? 1 : 0

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config[0].arn,
      "${aws_s3_bucket.config[0].arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "ConfigBucketAccess"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.config[0].arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "AWS:SourceArn"
      values   = [local.config_source_arn]
    }
  }

  statement {
    sid    = "ConfigDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "AWS:SourceArn"
      values   = [local.config_source_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count = var.enable_config_recording ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  policy = data.aws_iam_policy_document.config_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.config]
}

resource "aws_iam_role" "config" {
  count = var.enable_config_recording ? 1 : 0

  name_prefix = "${substr(var.name_prefix, 0, 34)}-config-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count = var.enable_config_recording ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  count = var.enable_config_recording ? 1 : 0

  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.enable_config_recording ? 1 : 0

  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.enable_config_recording ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_aggregate_authorization" "central" {
  count = var.enable_config_aggregation_authorization ? 1 : 0

  account_id            = var.central_config_account_id
  authorized_aws_region = var.central_config_region
}

resource "aws_s3_bucket" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket_prefix = substr("${var.name_prefix}-cloudtrail-", 0, 37)
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket                  = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "cloudtrail-retention"
    status = "Enabled"
    filter {}

    expiration {
      days = var.cloudtrail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail]
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail[0].arn,
      "${aws_s3_bucket.cloudtrail[0].arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "CloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail[0].arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.created_cloudtrail_arn]
    }
  }

  statement {
    sid    = "CloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.created_cloudtrail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

resource "aws_cloudtrail" "management" {
  count = var.cloudtrail_mode == "create" ? 1 : 0

  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

data "aws_iam_policy_document" "collector_assume" {
  count = var.create_collector_role ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = sort(tolist(local.collector_principal_arns))
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.collector_external_id]
    }
  }
}

resource "aws_iam_role" "collector" {
  count = var.create_collector_role ? 1 : 0

  name                 = coalesce(var.collector_role_name, "${var.name_prefix}-collector")
  assume_role_policy   = data.aws_iam_policy_document.collector_assume[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "collector" {
  count = var.create_collector_role ? 1 : 0

  name = "ec2-describe-only"
  role = aws_iam_role.collector[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DescribeEc2InventoryOnly"
      Effect   = "Allow"
      Action   = ["ec2:Describe*"]
      Resource = ["*"]
    }]
  })
}

resource "aws_cloudwatch_event_rule" "ec2_hint" {
  for_each = {
    for kind, pattern in local.event_patterns :
    kind => pattern if var.central_event_bus_arn != null
  }

  name          = local.rule_names[each.key]
  description   = "Forward supported ${data.aws_region.current.region} EC2 ${each.key} inventory hints to the central bus"
  event_pattern = jsonencode(each.value)
  state         = var.enable_event_forwarding ? "ENABLED" : "DISABLED"
}

data "aws_iam_policy_document" "eventbridge_assume" {
  count = var.central_event_bus_arn != null ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = values(aws_cloudwatch_event_rule.ec2_hint)[*].arn
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "event_forwarder" {
  count = var.central_event_bus_arn != null ? 1 : 0

  name_prefix        = "${substr(var.name_prefix, 0, 18)}-event-forward-"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume[0].json
}

resource "aws_iam_role_policy" "event_forwarder" {
  count = var.central_event_bus_arn != null ? 1 : 0

  name = "put-events-central-bus-only"
  role = aws_iam_role.event_forwarder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PutOnlyToCentralBus"
      Effect   = "Allow"
      Action   = ["events:PutEvents"]
      Resource = [var.central_event_bus_arn]
    }]
  })
}

resource "aws_cloudwatch_event_target" "central" {
  for_each = aws_cloudwatch_event_rule.ec2_hint

  rule     = each.value.name
  arn      = var.central_event_bus_arn
  role_arn = aws_iam_role.event_forwarder[0].arn
}

output "collector_role_arn" {
  value = try(aws_iam_role.collector[0].arn, null)
}

output "config_bucket_name" {
  value = try(aws_s3_bucket.config[0].id, null)
}

output "forwarding_rule_arn" {
  value = try(aws_cloudwatch_event_rule.ec2_hint["cloudtrail"].arn, null)
}

output "forwarding_rule_arns" {
  value = { for kind, rule in aws_cloudwatch_event_rule.ec2_hint : kind => rule.arn }
}

output "cloudtrail_arn" {
  description = "Created or explicitly referenced management trail supporting API-event forwarding."
  value       = local.effective_cloudtrail_arn
}

output "signal_region" {
  description = "Only this provider region's EventBridge hints are forwarded by this module instance."
  value       = data.aws_region.current.region
}
