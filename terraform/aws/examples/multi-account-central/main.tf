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

variable "name_prefix" {
  description = "Synthetic default; override from an ignored private tfvars file."
  type        = string
  default     = "scan-central"
}

variable "vpc_cidr" {
  description = "Canonical created-VPC CIDR."
  type        = string
  default     = "198.51.100.0/24"
}

variable "nat_gateway_mode" {
  description = "Created-VPC NAT topology."
  type        = string
  default     = "single"
}

variable "existing_config_aggregator_name" {
  description = "Synthetic existing aggregator name; override before apply."
  type        = string
  default     = "example-central-aggregator"
}

variable "allowed_member_account_ids" {
  description = "Synthetic central-bus member allowlist; override before apply."
  type        = set(string)
  default     = ["123456789012"]
}

variable "allowed_organization_id" {
  description = "Optional organization boundary in place of exact bus principals."
  type        = string
  default     = null
}

variable "authorized_account_ids" {
  description = "Synthetic inventory and dispatch scope; override before apply."
  type        = set(string)
  default     = ["123456789012"]
}

variable "member_collector_role_arns" {
  description = "Synthetic member collector roles keyed by account; override before apply."
  type        = map(string)
  default = {
    "123456789012" = "arn:aws:iam::123456789012:role/example-member-collector"
  }
}

variable "member_collector_external_ids" {
  description = "Private external IDs paired with member_collector_role_arns."
  type        = map(string)
  sensitive   = true
  default = {
    "123456789012" = "synthetic-example-external-id"
  }
}

variable "eks_api_client_security_group_ids" {
  description = "Runner or VPN security groups with private EKS API reachability."
  type        = set(string)
  default     = []
}

variable "eks_installer_principal_arns" {
  description = "IAM roles or users explicitly authorized to run the Helm install."
  type        = set(string)
  default     = []
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
      Environment = var.name_prefix
    }
  }
}

module "portscanner" {
  source = "../../application"

  name_prefix      = var.name_prefix
  create_vpc       = true
  vpc_cidr         = var.vpc_cidr
  nat_gateway_mode = var.nat_gateway_mode

  config_mode                     = "existing"
  existing_config_aggregator_name = var.existing_config_aggregator_name

  create_central_event_bus      = true
  allowed_member_account_ids    = var.allowed_member_account_ids
  allowed_organization_id       = var.allowed_organization_id
  authorized_account_ids        = var.authorized_account_ids
  member_collector_role_arns    = var.member_collector_role_arns
  member_collector_external_ids = var.member_collector_external_ids

  deploy_runtime        = var.deploy_runtime
  run_migration         = var.run_migration
  install_operator      = var.install_operator
  enable_event_dispatch = var.enable_event_dispatch
  image_digests         = var.image_digests
  migration_checksum    = var.migration_checksum
  alarm_action_arns     = []
  ok_action_arns        = []

  eks_api_client_security_group_ids = var.eks_api_client_security_group_ids
  eks_installer_principal_arns      = var.eks_installer_principal_arns
}

output "central_event_bus_arn" {
  value = module.portscanner.central_event_bus_arn
}

output "repository_urls" {
  value = module.portscanner.repository_urls
}

output "deployment_state" {
  value = module.portscanner.deployment_state
}

output "signal_region" {
  value = module.portscanner.signal_region
}
