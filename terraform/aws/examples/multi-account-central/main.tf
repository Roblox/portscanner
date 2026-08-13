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
  description = "Fail-closed AWS account boundary for this central Terraform root."
  type        = string
  default     = "123456789012"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_deployment_account_id))
    error_message = "expected_deployment_account_id must be a 12-digit AWS account ID."
  }
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

variable "cloudtrail_mode" {
  description = "create, existing, or disabled for local central-account API-call hints."
  type        = string
  default     = "create"
}

variable "existing_cloudtrail_arn" {
  description = "Existing central-account management trail ARN when cloudtrail_mode is existing."
  type        = string
  default     = null
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

variable "allowed_target_cidrs" {
  description = "Optional deployment-wide scanner allowlist."
  type        = set(string)
  default     = []
}

variable "denied_target_cidrs" {
  description = "Optional deployment-wide scanner denylist, enforced before the allowlist."
  type        = set(string)
  default     = []
}

variable "operator_max_concurrent_reconciles" {
  description = "Maximum concurrent Scanner reconciliations."
  type        = number
  default     = 4
}

variable "scanner_max_concurrent_pods" {
  description = "Hard cap on simultaneously active scanner Pods."
  type        = number
  default     = 4
}

variable "scanner_max_jobs" {
  description = "Hard cap on scanner Job objects."
  type        = number
  default     = 16
}

variable "scanner_min_rate" {
  description = "Minimum Nmap probe rate for each scanner Job."
  type        = number
  default     = 100
}

variable "scanner_max_rate" {
  description = "Maximum Nmap probe rate for each scanner Job."
  type        = number
  default     = 500
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

variable "eks_endpoint_public_access" {
  description = "Opt in to a restricted public EKS API endpoint for an evaluation."
  type        = bool
  default     = false
}

variable "eks_public_access_cidrs" {
  description = "Restricted canonical IPv4 CIDRs allowed to reach the opt-in public EKS API endpoint."
  type        = set(string)
  default     = []
}

variable "eks_installer_principal_arns" {
  description = "IAM roles or users explicitly authorized to run the Helm install."
  type        = set(string)
  default     = []
}

variable "lambda_architecture" {
  description = "arm64 or x86_64; must match node_ami_type and published images."
  type        = string
  default     = "arm64"
}

variable "node_ami_type" {
  description = "EKS managed-node AMI type matching lambda_architecture."
  type        = string
  default     = "AL2023_ARM_64_STANDARD"
}

variable "node_instance_types" {
  description = "EKS instance types compatible with node_ami_type."
  type        = list(string)
  default     = ["t4g.medium"]
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

variable "enable_automatic_inventory" {
  type    = bool
  default = false
}

variable "canary_mode" {
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
  region              = var.aws_region
  allowed_account_ids = [var.expected_deployment_account_id]

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
  cloudtrail_mode                 = var.cloudtrail_mode
  existing_cloudtrail_arn         = var.existing_cloudtrail_arn

  create_central_event_bus           = true
  allowed_member_account_ids         = var.allowed_member_account_ids
  allowed_organization_id            = var.allowed_organization_id
  authorized_account_ids             = var.authorized_account_ids
  allowed_target_cidrs               = var.allowed_target_cidrs
  denied_target_cidrs                = var.denied_target_cidrs
  operator_max_concurrent_reconciles = var.operator_max_concurrent_reconciles
  scanner_max_concurrent_pods        = var.scanner_max_concurrent_pods
  scanner_max_jobs                   = var.scanner_max_jobs
  scanner_min_rate                   = var.scanner_min_rate
  scanner_max_rate                   = var.scanner_max_rate
  member_collector_role_arns         = var.member_collector_role_arns
  member_collector_external_ids      = var.member_collector_external_ids

  deploy_runtime                   = var.deploy_runtime
  run_migration                    = var.run_migration
  install_operator                 = var.install_operator
  enable_event_dispatch            = var.enable_event_dispatch
  periodic_snapshots_enabled       = var.enable_automatic_inventory
  periodic_coverage_enabled        = var.enable_automatic_inventory
  signal_hints_enabled             = var.enable_automatic_inventory
  processor_reconciliation_enabled = var.enable_automatic_inventory
  canary_mode                      = var.canary_mode
  image_digests                    = var.image_digests
  migration_checksum               = var.migration_checksum
  alarm_action_arns                = []
  ok_action_arns                   = []

  eks_api_client_security_group_ids = var.eks_api_client_security_group_ids
  eks_endpoint_public_access        = var.eks_endpoint_public_access
  eks_public_access_cidrs           = var.eks_public_access_cidrs
  eks_installer_principal_arns      = var.eks_installer_principal_arns
  lambda_architecture               = var.lambda_architecture
  node_ami_type                     = var.node_ami_type
  node_instance_types               = var.node_instance_types
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

output "workload_architecture" {
  value = module.portscanner.workload_architecture
}

output "emergency_pause_controls" {
  value = module.portscanner.emergency_pause_controls
}

output "function_arns" {
  value = module.portscanner.function_arns
}

output "scanner_egress_public_ips" {
  value = module.portscanner.scanner_egress_public_ips
}

output "signal_region" {
  value = module.portscanner.signal_region
}

output "external_finding_queue_url" {
  value = module.portscanner.finding_queue_url
}

output "external_finding_queue_arn" {
  value = module.portscanner.finding_queue_arn
}

output "external_finding_bucket_name" {
  value = module.portscanner.finding_bucket_name
}

output "external_finding_bucket_arn" {
  value = module.portscanner.finding_bucket_arn
}
