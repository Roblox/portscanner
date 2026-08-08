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
  description = "Deployment region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Synthetic default; override from an ignored private tfvars file."
  type        = string
  default     = "scan-example"
}

variable "vpc_cidr" {
  description = "Canonical created-VPC CIDR."
  type        = string
  default     = "192.0.2.0/24"
}

variable "availability_zones" {
  description = "Optional explicit created-VPC availability zones."
  type        = list(string)
  default     = null
}

variable "az_count" {
  description = "Created-VPC availability-zone count."
  type        = number
  default     = 2
}

variable "nat_gateway_mode" {
  description = "Created-VPC NAT topology."
  type        = string
  default     = "single"
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

variable "ecr_untagged_image_expiration_days" {
  description = "Optional untagged-only ECR expiration; null disables expiration."
  type        = number
  default     = null
}

variable "alarm_action_arns" {
  type    = list(string)
  default = []
}

variable "ok_action_arns" {
  type    = list(string)
  default = []
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
  description = "Digests produced by an external image build pipeline."
  type        = map(string)
  default     = {}
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

  name_prefix        = var.name_prefix
  create_vpc         = true
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  az_count           = var.az_count
  nat_gateway_mode   = var.nat_gateway_mode

  create_central_event_bus = false
  authorized_account_ids   = var.authorized_account_ids

  deploy_runtime        = var.deploy_runtime
  run_migration         = var.run_migration
  install_operator      = var.install_operator
  enable_event_dispatch = var.enable_event_dispatch
  image_digests         = var.image_digests
  migration_checksum    = var.migration_checksum
  alarm_action_arns     = var.alarm_action_arns
  ok_action_arns        = var.ok_action_arns

  eks_api_client_security_group_ids = var.eks_api_client_security_group_ids
  eks_installer_principal_arns      = var.eks_installer_principal_arns

  ecr_untagged_image_expiration_days = var.ecr_untagged_image_expiration_days

  database_instance_count         = 1
  database_deletion_protection    = false
  database_skip_final_snapshot    = true
  dynamodb_point_in_time_recovery = false

  node_desired_size  = 1
  node_min_size      = 1
  node_max_size      = 2
  node_capacity_type = "SPOT"
}

output "repository_urls" {
  value = module.portscanner.repository_urls
}

output "deployment_state" {
  value = module.portscanner.deployment_state
}

output "external_finding_queue_url" {
  value = module.portscanner.finding_queue_url
}
