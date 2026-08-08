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
  description = "Prefix for Config, CloudTrail, and EventBridge resources."
  type        = string
}

variable "signal_queue_arn" {
  description = "Central SQS queue that receives filtered EC2 write hints."
  type        = string
}

variable "signal_dead_letter_queue_arn" {
  description = "Dead-letter queue used when EventBridge cannot deliver a supported hint."
  type        = string
}

variable "enable_event_dispatch" {
  description = "Activate rules and targets only after runtime migration and installation."
  type        = bool
  default     = false
}

variable "config_mode" {
  description = "create builds a recorder and explicitly current-region aggregator, existing accepts an aggregator, and disabled omits Config."
  type        = string
  default     = "create"

  validation {
    condition     = contains(["create", "existing", "disabled"], var.config_mode)
    error_message = "config_mode must be create, existing, or disabled."
  }
}

variable "config_delivery_bucket_name" {
  description = "Secure bucket used by a created AWS Config delivery channel."
  type        = string
}

variable "existing_config_aggregator_name" {
  description = "Existing Config aggregator name when config_mode is existing."
  type        = string
  default     = null
}

variable "existing_cloudtrail_arn" {
  description = "Existing multi-region management CloudTrail ARN. A trail is created when null."
  type        = string
  default     = null

  validation {
    condition     = var.existing_cloudtrail_arn == null || can(regex("^arn:[^:]+:cloudtrail:[^:]+:[0-9]{12}:trail/.+$", var.existing_cloudtrail_arn))
    error_message = "existing_cloudtrail_arn must be a CloudTrail trail ARN."
  }
}

variable "cloudtrail_name" {
  description = "Name for the required created management trail."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Secure S3 bucket for a created management trail."
  type        = string
}

variable "create_central_event_bus" {
  description = "Create a custom bus to accept filtered hints from authorized member accounts."
  type        = bool
  default     = true
}

variable "allowed_member_account_ids" {
  description = "Exact member account IDs allowed to call PutEvents on the central bus."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.allowed_member_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "Every allowed member account ID must be 12 digits."
  }
}

variable "allowed_organization_id" {
  description = "Optional organization ID used instead of an account allowlist. No Organizations API call is made."
  type        = string
  default     = null

  validation {
    condition     = var.allowed_organization_id == null || can(regex("^o-[a-z0-9]{10,32}$", var.allowed_organization_id))
    error_message = "allowed_organization_id must look like o- followed by 10-32 lowercase letters or digits."
  }
}

variable "authorized_account_ids" {
  description = "Exact account scopes whose hints may reach inventory."
  type        = set(string)
  default     = []
}

variable "config_aggregator_account_ids" {
  description = "Account scopes included by a created Config aggregator."
  type        = set(string)
  default     = []
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
  cloudtrail_event_pattern = {
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = local.allowed_cloudtrail_events
    }
  }
  state_change_event_pattern = {
    source        = ["aws.ec2"]
    "detail-type" = ["EC2 Instance State-change Notification"]
  }
  event_patterns = {
    cloudtrail = local.cloudtrail_event_pattern
    state      = local.state_change_event_pattern
  }
  local_event_patterns = {
    for kind, pattern in local.event_patterns :
    kind => merge(pattern, {
      account = [data.aws_caller_identity.current.account_id]
      }) if(
      length(var.authorized_account_ids) == 0 ||
      contains(var.authorized_account_ids, data.aws_caller_identity.current.account_id)
    )
  }
  local_rule_names = {
    cloudtrail = "${var.name_prefix}-ec2-write-hints"
    state      = "${var.name_prefix}-ec2-state-hints"
  }
  central_rule_names = {
    cloudtrail = "${var.name_prefix}-central-ingress"
    state      = "${var.name_prefix}-central-state-ingress"
  }
  bus_event_types = {
    CloudTrail = "AWS API Call via CloudTrail"
    State      = "EC2 Instance State-change Notification"
  }
  bus_account_ids = sort(tolist(setunion(
    var.allowed_member_account_ids,
    toset([data.aws_caller_identity.current.account_id])
  )))
  signal_account_ids = sort(tolist(
    length(var.authorized_account_ids) > 0 ?
    var.authorized_account_ids :
    toset(local.bus_account_ids)
  ))
  aggregator_account_ids = sort(tolist(
    length(var.config_aggregator_account_ids) > 0 ?
    var.config_aggregator_account_ids :
    toset([data.aws_caller_identity.current.account_id])
  ))
  recorded_config_regions = [data.aws_region.current.region]
}

resource "terraform_data" "signal_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition     = var.config_mode != "existing" ? true : try(length(var.existing_config_aggregator_name) > 0, false)
      error_message = "existing_config_aggregator_name is required when config_mode is existing."
    }

    precondition {
      condition     = !var.enable_event_dispatch || length(var.signal_queue_arn) > 0
      error_message = "A signal queue is required before event dispatch can be enabled."
    }

    precondition {
      condition = alltrue([
        for account_id in setunion(
          var.authorized_account_ids,
          var.config_aggregator_account_ids
        ) : can(regex("^[0-9]{12}$", account_id))
      ])
      error_message = "Signal and Config account scopes must contain 12-digit account IDs."
    }
  }
}

resource "aws_iam_role" "config" {
  count = var.config_mode == "create" ? 1 : 0

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
  count = var.config_mode == "create" ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  count = var.config_mode == "create" ? 1 : 0

  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.config_mode == "create" ? 1 : 0

  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.config_delivery_bucket_name
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.config_mode == "create" ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_aggregate_authorization" "self" {
  count = var.config_mode == "create" ? 1 : 0

  account_id            = data.aws_caller_identity.current.account_id
  authorized_aws_region = data.aws_region.current.region
}

resource "aws_config_configuration_aggregator" "this" {
  count = var.config_mode == "create" ? 1 : 0

  name = "${var.name_prefix}-accounts"

  account_aggregation_source {
    account_ids = local.aggregator_account_ids
    all_regions = false
    regions     = local.recorded_config_regions
  }

  depends_on = [aws_config_aggregate_authorization.self]
}

resource "aws_cloudtrail" "management" {
  count = var.existing_cloudtrail_arn == null ? 1 : 0

  name                          = var.cloudtrail_name
  s3_bucket_name                = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }
}

resource "aws_cloudwatch_event_bus" "central" {
  count = var.create_central_event_bus ? 1 : 0
  name  = "${var.name_prefix}-central"
}

data "aws_iam_policy_document" "central_bus" {
  count = var.create_central_event_bus ? 1 : 0

  dynamic "statement" {
    for_each = {
      for kind, detail_type in local.bus_event_types :
      kind => detail_type if var.allowed_organization_id == null
    }
    content {
      sid       = "AuthorizedAccounts${statement.key}"
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.central[0].arn]

      principals {
        type = "AWS"
        identifiers = [
          for account_id in local.bus_account_ids :
          "arn:${data.aws_partition.current.partition}:iam::${account_id}:root"
        ]
      }

      condition {
        test     = "StringEquals"
        variable = "events:source"
        values   = ["aws.ec2"]
      }

      condition {
        test     = "StringEquals"
        variable = "events:detail-type"
        values   = [statement.value]
      }
    }
  }

  dynamic "statement" {
    for_each = {
      for kind, detail_type in local.bus_event_types :
      kind => detail_type if var.allowed_organization_id != null
    }
    content {
      sid       = "AuthorizedOrganization${statement.key}"
      effect    = "Allow"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.central[0].arn]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [var.allowed_organization_id]
      }

      condition {
        test     = "StringEquals"
        variable = "events:source"
        values   = ["aws.ec2"]
      }

      condition {
        test     = "StringEquals"
        variable = "events:detail-type"
        values   = [statement.value]
      }
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "central" {
  count = var.create_central_event_bus ? 1 : 0

  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  policy         = data.aws_iam_policy_document.central_bus[0].json
}

resource "aws_cloudwatch_event_rule" "local" {
  for_each = local.local_event_patterns

  name          = local.local_rule_names[each.key]
  description   = "Supported ${data.aws_region.current.region} local EC2 ${each.key} inventory hints"
  event_pattern = jsonencode(each.value)
  state         = var.enable_event_dispatch ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "local_signal_queue" {
  for_each = aws_cloudwatch_event_rule.local

  rule = each.value.name
  arn  = var.signal_queue_arn

  dead_letter_config {
    arn = var.signal_dead_letter_queue_arn
  }
}

resource "aws_cloudwatch_event_rule" "central" {
  for_each = {
    for kind, pattern in local.event_patterns :
    kind => pattern if var.create_central_event_bus
  }

  name           = local.central_rule_names[each.key]
  description    = "Supported member EC2 ${each.key} inventory hints delivered to ${data.aws_region.current.region}"
  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  event_pattern = jsonencode(merge(each.value, {
    account = local.signal_account_ids
  }))
  state = var.enable_event_dispatch ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "central_signal_queue" {
  for_each = aws_cloudwatch_event_rule.central

  rule           = each.value.name
  event_bus_name = aws_cloudwatch_event_bus.central[0].name
  arn            = var.signal_queue_arn

  dead_letter_config {
    arn = var.signal_dead_letter_queue_arn
  }
}

output "config_aggregator_name" {
  value = (
    var.config_mode == "create" ? aws_config_configuration_aggregator.this[0].name :
    var.config_mode == "existing" ? var.existing_config_aggregator_name :
    null
  )
}

output "cloudtrail_arn" {
  value = var.existing_cloudtrail_arn != null ? var.existing_cloudtrail_arn : aws_cloudtrail.management[0].arn
}

output "central_event_bus_arn" {
  value = var.create_central_event_bus ? aws_cloudwatch_event_bus.central[0].arn : null
}

output "central_event_bus_name" {
  value = var.create_central_event_bus ? aws_cloudwatch_event_bus.central[0].name : null
}

output "signal_rule_arns" {
  value = concat(
    values(aws_cloudwatch_event_rule.local)[*].arn,
    values(aws_cloudwatch_event_rule.central)[*].arn
  )
}

output "signal_region" {
  description = "Region containing the local rules and central event bus; local hot-path signals cover only this region."
  value       = data.aws_region.current.region
}

output "created_config_source_regions" {
  description = "Explicit source regions included by a created aggregator. Empty when Config is existing or disabled."
  value       = var.config_mode == "create" ? local.recorded_config_regions : []
}
