terraform {
  required_version = "= 1.7.4"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.15.0"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "expected_deployment_account_id" {
  description = "Fail-closed AWS account boundary for this member Terraform root."
  type        = string
  default     = "123456789012"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_deployment_account_id))
    error_message = "expected_deployment_account_id must be a 12-digit AWS account ID."
  }
}

variable "name_prefix" {
  description = "Synthetic default; use a unique per-account/per-signal-region name."
  type        = string
  default     = "scan-member"
}

variable "enable_config_recording" {
  description = "Create a Config recorder in this provider region."
  type        = bool
  default     = false
}

variable "enable_config_aggregation_authorization" {
  description = "Authorize the configured central aggregator account and region."
  type        = bool
  default     = true
}

variable "central_config_account_id" {
  description = "Synthetic central account ID; override before apply."
  type        = string
  default     = "123456789012"
}

variable "central_config_region" {
  description = "Region containing the central Config aggregator."
  type        = string
  default     = "us-east-1"
}

variable "collector_role_name" {
  description = "Shared collector role name used across member accounts."
  type        = string
  default     = "example-member-collector"
}

variable "central_collector_principal_arns" {
  description = "Synthetic central collector roles; override before apply."
  type        = set(string)
  default = [
    "arn:aws:iam::123456789012:role/example-central-snapshot",
    "arn:aws:iam::123456789012:role/example-central-signals"
  ]
}

variable "collector_external_id" {
  description = "Private external ID shared with the central collector configuration."
  type        = string
  sensitive   = true
  default     = "synthetic-example-external-id"
}

variable "central_event_bus_arn" {
  description = "Synthetic central custom event bus ARN; override before apply."
  type        = string
  default     = "arn:aws:events:us-east-1:123456789012:event-bus/scan-central-central"
}

variable "enable_event_forwarding" {
  description = "Enable this provider region's filtered EventBridge rules."
  type        = bool
  default     = false
}

variable "cloudtrail_mode" {
  description = "create, existing, or disabled. Active API-event forwarding forbids disabled."
  type        = string
  default     = "disabled"
}

variable "existing_cloudtrail_arn" {
  description = "Existing member or organization management trail when cloudtrail_mode is existing."
  type        = string
  default     = null
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_deployment_account_id]

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Environment = var.name_prefix
    }
  }
}

module "member" {
  source = "../../member-account"

  name_prefix = var.name_prefix

  enable_config_recording                 = var.enable_config_recording
  enable_config_aggregation_authorization = var.enable_config_aggregation_authorization
  central_config_account_id               = var.central_config_account_id
  central_config_region                   = var.central_config_region

  create_collector_role            = true
  collector_role_name              = var.collector_role_name
  central_collector_principal_arns = var.central_collector_principal_arns
  collector_external_id            = var.collector_external_id

  central_event_bus_arn   = var.central_event_bus_arn
  enable_event_forwarding = var.enable_event_forwarding
  cloudtrail_mode         = var.cloudtrail_mode
  existing_cloudtrail_arn = var.existing_cloudtrail_arn
}

output "member_collector_role_arn" {
  value = module.member.collector_role_arn
}

output "forwarding_rule_arn" {
  value = module.member.forwarding_rule_arn
}

output "forwarding_rule_arns" {
  value = module.member.forwarding_rule_arns
}

output "signal_region" {
  value = module.member.signal_region
}

output "cloudtrail_arn" {
  value = module.member.cloudtrail_arn
}
