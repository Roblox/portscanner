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
      Environment = "example-existing-vpc"
    }
  }
}

module "portscanner" {
  source = "../../application"

  name_prefix = "scan-existing"
  create_vpc  = false

  # Synthetic IDs: replace all of these with subnets from one VPC. The module
  # verifies VPC membership, AZ spread, public-IP behavior, and route-table shape.
  existing_vpc_id = "vpc-0123456789abcdef0"
  existing_private_subnet_ids = [
    "subnet-0123456789abcdef0",
    "subnet-0123456789abcdef1"
  ]
  existing_isolated_subnet_ids = [
    "subnet-0123456789abcdef2",
    "subnet-0123456789abcdef3"
  ]

  config_mode              = "disabled"
  snapshot_regions         = ["us-east-1"]
  create_central_event_bus = false
  authorized_account_ids   = ["123456789012"]

  deploy_runtime        = var.deploy_runtime
  run_migration         = var.run_migration
  install_operator      = var.install_operator
  enable_event_dispatch = var.enable_event_dispatch
  image_digests         = var.image_digests
  migration_checksum    = var.migration_checksum
  alarm_action_arns     = []
  ok_action_arns        = []
}

output "repository_urls" {
  value = module.portscanner.repository_urls
}

output "validated_vpc_id" {
  value = module.portscanner.vpc_id
}
