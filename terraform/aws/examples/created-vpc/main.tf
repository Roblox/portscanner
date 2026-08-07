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
      Environment = "example-created-vpc"
    }
  }
}

module "portscanner" {
  source = "../../application"

  name_prefix      = "scan-example"
  create_vpc       = true
  vpc_cidr         = "192.0.2.0/24"
  az_count         = 2
  nat_gateway_mode = "single"

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
