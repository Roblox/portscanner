locals {
  configured_architecture = var.environment.scanner.architecture
  configured_node_ami_type = (
    local.configured_architecture == "arm64" ?
    "AL2023_ARM_64_STANDARD" :
    "AL2023_x86_64_STANDARD"
  )
  configured_node_instance_types = [var.environment.scanner.node_instance_type]

  workload_architecture = coalesce(var.lambda_architecture, local.configured_architecture)
  node_ami_type         = coalesce(var.node_ami_type, local.configured_node_ami_type)
  node_instance_types   = var.node_instance_types == null ? local.configured_node_instance_types : var.node_instance_types

  config_mode = (
    var.environment.integrations.recurring_inventory_enabled ?
    var.environment.integrations.config_mode :
    "disabled"
  )
  cloudtrail_mode = (
    var.environment.integrations.signal_hints_enabled ?
    var.environment.integrations.cloudtrail_mode :
    "disabled"
  )

  destroy_data = (
    var.environment.retention.disposable &&
    var.environment.retention.destroy_data_on_teardown
  )
  database_skip_final_snapshot = local.destroy_data
  database_final_snapshot_identifier = (
    local.database_skip_final_snapshot ?
    null :
    "${var.environment.name}-final"
  )
  retirement_environment = merge(
    var.environment,
    {
      managed_canary = merge(
        var.environment.managed_canary,
        { enabled = true }
      )
    }
  )
  retirement_configuration_fingerprint = sha256(jsonencode(local.retirement_environment))
}

provider "aws" {
  region              = var.environment.aws.region
  allowed_account_ids = [var.environment.aws.account_id]

  default_tags {
    tags = {
      Environment = var.environment.name
      ManagedBy   = "Terraform"
      Project     = "portscanner"
    }
  }
}

resource "terraform_data" "canonical_configuration" {
  input = {
    environment_name                     = var.environment.name
    environment                          = var.environment
    retirement_configuration_fingerprint = local.retirement_configuration_fingerprint
  }

  lifecycle {
    precondition {
      condition = (
        var.lambda_architecture == null ||
        var.lambda_architecture == local.configured_architecture
      )
      error_message = "Generated lambda_architecture does not match environment.scanner.architecture."
    }

    precondition {
      condition = (
        var.node_ami_type == null ||
        var.node_ami_type == local.configured_node_ami_type
      )
      error_message = "Generated node_ami_type does not match environment.scanner.architecture."
    }

    precondition {
      condition = (
        var.node_instance_types == null ||
        var.node_instance_types == local.configured_node_instance_types
      )
      error_message = "Generated node_instance_types do not match environment.scanner.node_instance_type."
    }
  }
}

module "portscanner" {
  source = "../application"

  name_prefix        = var.environment.name
  create_vpc         = true
  vpc_cidr           = var.environment.network.vpc_cidr
  availability_zones = length(var.environment.network.availability_zones) == 0 ? null : var.environment.network.availability_zones
  az_count           = var.environment.network.az_count
  nat_gateway_mode   = var.environment.network.nat_gateway_mode

  managed_canary_enabled       = var.environment.managed_canary.enabled
  managed_canary_vpc_cidr      = var.environment.managed_canary.vpc_cidr
  managed_canary_instance_type = var.environment.managed_canary.instance_type

  config_mode                     = local.config_mode
  existing_config_aggregator_name = length(var.environment.integrations.existing_config_aggregator_name) == 0 ? null : var.environment.integrations.existing_config_aggregator_name
  snapshot_regions                = var.environment.integrations.snapshot_regions
  cloudtrail_mode                 = local.cloudtrail_mode
  existing_cloudtrail_arn         = length(var.environment.integrations.existing_cloudtrail_arn) == 0 ? null : var.environment.integrations.existing_cloudtrail_arn

  create_central_event_bus = false
  authorized_account_ids   = var.environment.integrations.authorized_account_ids
  allowed_target_cidrs     = var.environment.integrations.allowed_target_cidrs
  denied_target_cidrs      = var.environment.integrations.denied_target_cidrs
  inventory_allowed_eni_interface_types = (
    var.environment.integrations.allowed_eni_interface_types
  )
  inventory_required_target_tag_key = (
    var.environment.integrations.required_target_tag_key
  )
  inventory_required_target_tag_value = (
    var.environment.integrations.required_target_tag_value
  )
  operator_max_concurrent_reconciles = var.environment.scanner.operator_max_concurrent_reconciles
  scanner_max_concurrent_pods        = var.environment.scanner.max_concurrent_pods
  scanner_max_jobs                   = var.environment.scanner.max_jobs
  scanner_min_rate                   = var.environment.scanner.min_rate
  scanner_max_rate                   = var.environment.scanner.max_rate

  deploy_runtime        = var.deploy_runtime
  run_migration         = var.run_migration
  install_operator      = var.install_operator
  enable_event_dispatch = var.enable_event_dispatch
  periodic_snapshots_enabled = (
    var.enable_automatic_inventory &&
    var.environment.integrations.recurring_inventory_enabled
  )
  periodic_coverage_enabled = (
    var.enable_automatic_inventory &&
    var.environment.integrations.recurring_inventory_enabled
  )
  signal_hints_enabled = (
    var.enable_automatic_inventory &&
    var.environment.integrations.signal_hints_enabled
  )
  processor_reconciliation_enabled = (
    var.enable_automatic_inventory &&
    var.environment.integrations.recurring_inventory_enabled
  )
  finding_export_enabled = var.environment.integrations.finding_export_enabled
  canary_mode            = var.canary_mode
  image_digests          = var.image_digests
  migration_checksum     = var.migration_checksum

  eks_endpoint_public_access   = true
  eks_public_access_cidrs      = [var.environment.runner.restricted_public_cidr]
  eks_installer_principal_arns = [var.environment.runner.eks_installer_principal_arn]
  lambda_architecture          = local.workload_architecture
  node_ami_type                = local.node_ami_type
  node_instance_types          = local.node_instance_types

  bucket_expiration_days             = var.environment.retention.bucket_expiration_days
  ecr_untagged_image_expiration_days = var.environment.retention.ecr_untagged_image_days
  force_destroy_buckets              = local.destroy_data
  force_delete_repositories          = local.destroy_data
  lambda_log_retention_days          = var.environment.retention.lambda_log_days

  database_instance_count            = 1
  database_backup_retention_days     = var.environment.retention.database_backup_days
  database_deletion_protection       = !var.environment.retention.disposable
  database_skip_final_snapshot       = local.database_skip_final_snapshot
  database_final_snapshot_identifier = local.database_final_snapshot_identifier
  dynamodb_point_in_time_recovery    = !var.environment.retention.disposable

  node_desired_size  = 1
  node_min_size      = 1
  node_max_size      = 2
  node_capacity_type = "SPOT"
}
