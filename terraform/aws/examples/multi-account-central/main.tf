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

variable "deploy_runtime" {
  type    = bool
  default = false
}

variable "run_migration" {
  type    = bool
  default = false
}

variable "install_operator" {
  type    = bool
  default = false
}

variable "enable_event_dispatch" {
  type    = bool
  default = false
}

variable "image_digests" {
  type    = map(string)
  default = {}
}

variable "migration_checksum" {
  type    = string
  default = ""
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Environment = "example-multi-account-central"
    }
  }
}

module "portscanner" {
  source = "../../application"

  name_prefix      = "scan-central"
  create_vpc       = true
  vpc_cidr         = "198.51.100.0/24"
  nat_gateway_mode = "single"

  config_mode                     = "existing"
  existing_config_aggregator_name = "example-central-aggregator"

  create_central_event_bus   = true
  allowed_member_account_ids = ["123456789012"]
  allowed_organization_id    = null
  authorized_account_ids     = ["123456789012"]
  member_collector_role_arns = {
    "123456789012" = "arn:aws:iam::123456789012:role/example-member-collector"
  }
  member_collector_external_ids = {
    "123456789012" = "synthetic-example-external-id"
  }

  deploy_runtime        = var.deploy_runtime
  run_migration         = var.run_migration
  install_operator      = var.install_operator
  enable_event_dispatch = var.enable_event_dispatch
  image_digests         = var.image_digests
  migration_checksum    = var.migration_checksum
  alarm_action_arns     = []
  ok_action_arns        = []
}

output "central_event_bus_arn" {
  value = module.portscanner.central_event_bus_arn
}

output "repository_urls" {
  value = module.portscanner.repository_urls
}
