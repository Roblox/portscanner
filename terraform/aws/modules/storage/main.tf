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
  description = "Short prefix used for generated bucket, queue, and table names."
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "Maximum timeout of queue-triggered Lambda functions."
  type        = number
  default     = 60
}

variable "queue_visibility_timeout_seconds" {
  description = "Queue visibility timeout; must be at least six times the Lambda timeout."
  type        = number
  default     = 360

  validation {
    condition     = var.queue_visibility_timeout_seconds >= 1 && var.queue_visibility_timeout_seconds <= 43200
    error_message = "queue_visibility_timeout_seconds must be between 1 and 43200."
  }
}

variable "queue_retention_seconds" {
  description = "Retention for primary queues."
  type        = number
  default     = 345600

  validation {
    condition     = var.queue_retention_seconds >= 60 && var.queue_retention_seconds <= 1209600
    error_message = "queue_retention_seconds must be between 60 and 1209600."
  }
}

variable "dead_letter_retention_seconds" {
  description = "Retention for dead-letter queues."
  type        = number
  default     = 1209600
}

variable "max_receive_count" {
  description = "Receives before a message is moved to its dead-letter queue."
  type        = number
  default     = 5
}

variable "bucket_expiration_days" {
  description = "Current-object expiration by bucket purpose. Increase results/findings/CloudTrail retention for production."
  type        = map(number)
  default = {
    events     = 30
    results    = 90
    findings   = 365
    cloudtrail = 365
  }
}

variable "force_destroy_buckets" {
  description = "Delete all object versions during destroy. Keep false for retained environments; use true only for disposable sandboxes."
  type        = bool
  default     = false
}

variable "noncurrent_expiration_days" {
  description = "Noncurrent-version expiration for all data buckets."
  type        = number
  default     = 30
}

variable "dynamodb_point_in_time_recovery" {
  description = "Enable PITR on the inventory and dispatch tables. Production should set this true."
  type        = bool
  default     = false
}

variable "cloudtrail_source_arns" {
  description = "Exact CloudTrail ARNs allowed to write to the CloudTrail bucket."
  type        = list(string)
}

variable "enable_config_delivery" {
  description = "Allow AWS Config in this account to deliver snapshots beneath the events bucket config prefix."
  type        = bool
  default     = false
}

variable "signal_event_rule_arns" {
  description = "Exact EventBridge rule ARNs permitted to send to the central signal queue."
  type        = list(string)
  default     = []
}

variable "queue_age_alarm_threshold_seconds" {
  description = "Oldest-message age that alarms primary queues."
  type        = number
  default     = 900

  validation {
    condition     = var.queue_age_alarm_threshold_seconds >= 60 && var.queue_age_alarm_threshold_seconds <= 1209600
    error_message = "queue_age_alarm_threshold_seconds must be between 60 and 1209600."
  }
}

variable "alarm_action_arns" {
  description = "Existing action ARNs invoked when a storage alarm enters ALARM; empty creates alarms without actions."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.alarm_action_arns :
      can(regex("^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$", arn))
    ])
    error_message = "alarm_action_arns must contain valid ARN-shaped values."
  }
}

variable "ok_action_arns" {
  description = "Existing action ARNs invoked when a storage alarm returns to OK."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.ok_action_arns :
      can(regex("^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$", arn))
    ])
    error_message = "ok_action_arns must contain valid ARN-shaped values."
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  bucket_purposes   = toset(["events", "results", "findings", "cloudtrail"])
  queue_purposes    = toset(["signal", "priority", "coverage", "target-event", "result", "finding"])
  config_source_arn = "arn:${data.aws_partition.current.partition}:config:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"
}

resource "terraform_data" "storage_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition     = var.queue_visibility_timeout_seconds >= 6 * var.lambda_timeout_seconds
      error_message = "queue_visibility_timeout_seconds must be at least six times lambda_timeout_seconds."
    }

    precondition {
      condition     = alltrue([for purpose in local.bucket_purposes : lookup(var.bucket_expiration_days, purpose, 0) > 0])
      error_message = "bucket_expiration_days must contain a positive value for events, results, findings, and cloudtrail."
    }
  }
}

resource "aws_s3_bucket" "data" {
  for_each = local.bucket_purposes

  bucket_prefix = substr("${var.name_prefix}-${each.key}-", 0, 37)
  force_destroy = var.force_destroy_buckets

  tags = {
    Purpose = each.key
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  for_each = aws_s3_bucket.data

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  for_each = aws_s3_bucket.data

  bucket = each.value.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  for_each = aws_s3_bucket.data

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  for_each = aws_s3_bucket.data

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  for_each = aws_s3_bucket.data

  bucket = each.value.id

  rule {
    id     = "retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.bucket_expiration_days[each.key]
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_expiration_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

data "aws_iam_policy_document" "bucket" {
  for_each = aws_s3_bucket.data

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      each.value.arn,
      "${each.value.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "cloudtrail" ? [1] : []
    content {
      sid    = "CloudTrailAclCheck"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }

      actions   = ["s3:GetBucketAcl"]
      resources = [each.value.arn]

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = var.cloudtrail_source_arns
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "cloudtrail" ? [1] : []
    content {
      sid    = "CloudTrailWrite"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }

      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = var.cloudtrail_source_arns
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "events" && var.enable_config_delivery ? [1] : []
    content {
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
      resources = [each.value.arn]

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

  dynamic "statement" {
    for_each = each.key == "events" && var.enable_config_delivery ? [1] : []
    content {
      sid    = "ConfigDelivery"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }

      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

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
}

resource "aws_s3_bucket_policy" "data" {
  for_each = aws_s3_bucket.data

  bucket = each.value.id
  policy = data.aws_iam_policy_document.bucket[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.data]
}

resource "aws_sqs_queue" "dead_letter" {
  for_each = local.queue_purposes

  name                      = "${var.name_prefix}-${each.key}-dlq"
  message_retention_seconds = var.dead_letter_retention_seconds
  sqs_managed_sse_enabled   = true

  tags = {
    Purpose = "${each.key}-dead-letter"
  }
}

resource "aws_sqs_queue" "main" {
  for_each = local.queue_purposes

  name                       = "${var.name_prefix}-${each.key}"
  message_retention_seconds  = var.queue_retention_seconds
  visibility_timeout_seconds = var.queue_visibility_timeout_seconds
  sqs_managed_sse_enabled    = true
  receive_wait_time_seconds  = 20
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = {
    Purpose = each.key
  }
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  for_each = aws_sqs_queue.main

  alarm_name          = "${each.value.name}-oldest-message-age"
  alarm_description   = "Oldest message on the ${each.key} queue has exceeded ${var.queue_age_alarm_threshold_seconds} seconds."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = var.queue_age_alarm_threshold_seconds
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns

  dimensions = {
    QueueName = each.value.name
  }
}

resource "aws_cloudwatch_metric_alarm" "dead_letter_messages" {
  for_each = aws_sqs_queue.dead_letter

  alarm_name          = "${each.value.name}-messages-visible"
  alarm_description   = "The ${each.key} dead-letter queue contains at least one visible message."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns

  dimensions = {
    QueueName = each.value.name
  }
}

resource "aws_sqs_queue_redrive_allow_policy" "dead_letter" {
  for_each = aws_sqs_queue.dead_letter

  queue_url = each.value.url
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.main[each.key].arn]
  })
}

data "aws_iam_policy_document" "dead_letter_queue" {
  for_each = aws_sqs_queue.dead_letter

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["sqs:*"]
    resources = [each.value.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "signal" && length(var.signal_event_rule_arns) > 0 ? [1] : []
    content {
      sid    = "AllowExactEventRulesAsDlq"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }

      actions   = ["sqs:SendMessage"]
      resources = [each.value.arn]

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = var.signal_event_rule_arns
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }
}

resource "aws_sqs_queue_policy" "dead_letter" {
  for_each = aws_sqs_queue.dead_letter

  queue_url = each.value.url
  policy    = data.aws_iam_policy_document.dead_letter_queue[each.key].json
}

data "aws_iam_policy_document" "queue" {
  for_each = aws_sqs_queue.main

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["sqs:*"]
    resources = [each.value.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "signal" && length(var.signal_event_rule_arns) > 0 ? [1] : []
    content {
      sid    = "AllowExactEventRules"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }

      actions   = ["sqs:SendMessage"]
      resources = [each.value.arn]

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = var.signal_event_rule_arns
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = contains(["result", "finding"], each.key) ? [1] : []
    content {
      sid    = each.key == "result" ? "AllowResultBucketNotifications" : "AllowFindingBucketNotifications"
      effect = "Allow"

      principals {
        type        = "Service"
        identifiers = ["s3.amazonaws.com"]
      }

      actions   = ["sqs:SendMessage"]
      resources = [each.value.arn]

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values = [
          aws_s3_bucket.data[each.key == "result" ? "results" : "findings"].arn
        ]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }
}

resource "aws_sqs_queue_policy" "main" {
  for_each = aws_sqs_queue.main

  queue_url = each.value.url
  policy    = data.aws_iam_policy_document.queue[each.key].json
}

resource "aws_s3_bucket_notification" "results" {
  bucket = aws_s3_bucket.data["results"].id

  queue {
    queue_arn     = aws_sqs_queue.main["result"].arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "results/"
    filter_suffix = "scan-result.json"
  }

  depends_on = [
    aws_s3_bucket_policy.data,
    aws_sqs_queue_policy.main
  ]
}

resource "aws_s3_bucket_notification" "findings" {
  bucket = aws_s3_bucket.data["findings"].id

  queue {
    queue_arn     = aws_sqs_queue.main["finding"].arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "findings/"
  }

  depends_on = [
    aws_s3_bucket_policy.data,
    aws_sqs_queue_policy.main
  ]
}

resource "aws_dynamodb_table" "inventory" {
  name         = "${var.name_prefix}-inventory"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.dynamodb_point_in_time_recovery
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Purpose = "inventory"
  }
}

resource "aws_dynamodb_table" "dispatch" {
  name         = "${var.name_prefix}-dispatch"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "dispatch_id"

  attribute {
    name = "dispatch_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.dynamodb_point_in_time_recovery
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Purpose = "dispatch"
  }
}

output "bucket_names" {
  value = { for purpose, bucket in aws_s3_bucket.data : purpose => bucket.id }
}

output "bucket_arns" {
  value = { for purpose, bucket in aws_s3_bucket.data : purpose => bucket.arn }
}

output "queue_urls" {
  value = { for purpose, queue in aws_sqs_queue.main : purpose => queue.url }
}

output "queue_arns" {
  value = { for purpose, queue in aws_sqs_queue.main : purpose => queue.arn }
}

output "dead_letter_queue_arns" {
  value = { for purpose, queue in aws_sqs_queue.dead_letter : purpose => queue.arn }
}

output "table_names" {
  value = {
    inventory = aws_dynamodb_table.inventory.name
    dispatch  = aws_dynamodb_table.dispatch.name
  }
}

output "table_arns" {
  value = {
    inventory = aws_dynamodb_table.inventory.arn
    dispatch  = aws_dynamodb_table.dispatch.arn
  }
}

output "table_stream_arns" {
  value = {
    inventory = aws_dynamodb_table.inventory.stream_arn
  }
}

output "bucket_policy_ids" {
  value = { for purpose, policy in aws_s3_bucket_policy.data : purpose => policy.id }
}

output "alarm_names" {
  description = "CloudWatch storage alarm names keyed by alarm class and queue purpose."
  value = {
    queue_age = {
      for purpose, alarm in aws_cloudwatch_metric_alarm.queue_age :
      purpose => alarm.alarm_name
    }
    dead_letter_messages = {
      for purpose, alarm in aws_cloudwatch_metric_alarm.dead_letter_messages :
      purpose => alarm.alarm_name
    }
  }
}

output "alarm_arns" {
  description = "CloudWatch storage alarm ARNs keyed by alarm class and queue purpose."
  value = {
    queue_age = {
      for purpose, alarm in aws_cloudwatch_metric_alarm.queue_age :
      purpose => alarm.arn
    }
    dead_letter_messages = {
      for purpose, alarm in aws_cloudwatch_metric_alarm.dead_letter_messages :
      purpose => alarm.arn
    }
  }
}
