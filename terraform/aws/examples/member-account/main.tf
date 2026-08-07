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

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Environment = "example-member-account"
    }
  }
}

module "member" {
  source = "../../member-account"

  name_prefix = "scan-member"

  enable_config_recording                 = false
  enable_config_aggregation_authorization = true
  central_config_account_id               = "123456789012"
  central_config_region                   = "us-east-1"

  create_collector_role = true
  collector_role_name   = "example-member-collector"
  central_collector_principal_arns = [
    "arn:aws:iam::123456789012:role/example-central-snapshot",
    "arn:aws:iam::123456789012:role/example-central-signals"
  ]
  collector_external_id = "synthetic-example-external-id"

  central_event_bus_arn   = "arn:aws:events:us-east-1:123456789012:event-bus/scan-central-central"
  enable_event_forwarding = false
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
