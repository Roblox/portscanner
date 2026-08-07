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
  default     = "scan-existing"
}

variable "existing_vpc_id" {
  description = "Synthetic VPC ID; override before planning against AWS."
  type        = string
  default     = "vpc-0123456789abcdef0"
}

variable "existing_public_subnet_ids" {
  description = "Optional existing public subnets, never used by workloads."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_ids" {
  description = "Synthetic private subnet IDs; override before planning against AWS."
  type        = list(string)
  default = [
    "subnet-0123456789abcdef0",
    "subnet-0123456789abcdef1"
  ]
}

variable "existing_isolated_subnet_ids" {
  description = "Synthetic isolated subnet IDs; override before planning against AWS."
  type        = list(string)
  default = [
    "subnet-0123456789abcdef2",
    "subnet-0123456789abcdef3"
  ]
}

variable "existing_private_subnet_egress_mode" {
  description = "Required live declaration: nat_gateway, transit_gateway, or vpc_endpoints."
  type        = string
  default     = null
}

variable "existing_private_vpc_endpoint_ids" {
  description = "Existing endpoint IDs keyed by required service for vpc_endpoints egress mode."
  type        = map(string)
  default     = {}
}

variable "existing_private_interface_endpoint_security_group_ids" {
  description = "One attached security group per required interface endpoint, keyed by service."
  type        = map(string)
  default     = {}
}

variable "snapshot_regions" {
  description = "Regions reconciled by direct EC2 snapshots; empty uses aws_region."
  type        = list(string)
  default     = []
}

variable "authorized_account_ids" {
  description = "Synthetic account scope; override before apply."
  type        = set(string)
  default     = ["123456789012"]
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

  name_prefix = var.name_prefix
  create_vpc  = false

  # Synthetic IDs: replace all of these with subnets from one VPC. The module
  # verifies VPC membership, AZ spread, public-IP behavior, routes, and egress.
  existing_vpc_id                                        = var.existing_vpc_id
  existing_public_subnet_ids                             = var.existing_public_subnet_ids
  existing_private_subnet_ids                            = var.existing_private_subnet_ids
  existing_isolated_subnet_ids                           = var.existing_isolated_subnet_ids
  existing_private_subnet_egress_mode                    = var.existing_private_subnet_egress_mode
  existing_private_vpc_endpoint_ids                      = var.existing_private_vpc_endpoint_ids
  existing_private_interface_endpoint_security_group_ids = var.existing_private_interface_endpoint_security_group_ids

  config_mode              = "disabled"
  snapshot_regions         = var.snapshot_regions
  create_central_event_bus = false
  authorized_account_ids   = var.authorized_account_ids

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

output "repository_urls" {
  value = module.portscanner.repository_urls
}

output "validated_vpc_id" {
  value = module.portscanner.vpc_id
}

output "deployment_state" {
  value = module.portscanner.deployment_state
}
