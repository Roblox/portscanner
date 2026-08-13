data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name                = var.name_prefix
  cluster_name        = "${local.name}-eks"
  cloudtrail_name     = "${local.name}-management"
  central_bus_name    = "${local.name}-central"
  local_signal_rule   = "${local.name}-ec2-write-hints"
  local_state_rule    = "${local.name}-ec2-state-hints"
  central_signal_rule = "${local.name}-central-ingress"
  central_state_rule  = "${local.name}-central-state-ingress"
  snapshot_backend    = var.config_mode == "disabled" ? "ec2" : "config"
  snapshot_regions = length(var.snapshot_regions) > 0 ? var.snapshot_regions : [
    data.aws_region.current.region
  ]
  periodic_snapshots_enabled       = var.periodic_snapshots_enabled
  periodic_coverage_enabled        = var.periodic_coverage_enabled
  signal_hints_enabled             = var.signal_hints_enabled
  processor_reconciliation_enabled = var.processor_reconciliation_enabled
  operator_chart_path              = abspath("${path.module}/../../../operator/chart/portscanner")

  cloudtrail_arn = (
    var.cloudtrail_mode == "create" ?
    "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}" :
    var.cloudtrail_mode == "existing" ? var.existing_cloudtrail_arn : null
  )

  signal_rule_arns = compact([
    var.cloudtrail_mode != "disabled" ? "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/${local.local_signal_rule}" : null,
    "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/${local.local_state_rule}",
    var.create_central_event_bus ? "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/${local.central_bus_name}/${local.central_signal_rule}" : null,
    var.create_central_event_bus ? "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/${local.central_bus_name}/${local.central_state_rule}" : null
  ])

  eks_cluster_arn = "arn:${data.aws_partition.current.partition}:eks:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:cluster/${local.cluster_name}"
  required_images = toset([
    "inventory",
    "generator",
    "parser",
    "processor",
    "migrator",
    "operator",
    "scanner"
  ])
  bus_authorized_account_ids = setunion(
    var.allowed_member_account_ids,
    toset([data.aws_caller_identity.current.account_id])
  )
  managed_canary_scanner_source_cidrs = concat(
    [for address in module.network.created_nat_public_ips : "${address}/32"],
    [
      for address in sort(tolist(var.managed_canary_scanner_source_ipv4s)) :
      "${address}/32"
    ]
  )
  managed_canary = var.managed_canary_enabled ? {
    account_id           = data.aws_caller_identity.current.account_id
    region               = data.aws_region.current.region
    network_interface_id = module.managed_canary[0].network_interface_id
    private_ip           = module.managed_canary[0].private_ip
    public_ip            = module.managed_canary[0].public_ip
    tag_key              = module.managed_canary[0].inventory_tag_key
    tag_value            = module.managed_canary[0].inventory_tag_value
    tcp_port             = module.managed_canary[0].listener_port
  } : null
  effective_authorized_account_ids = (
    var.managed_canary_enabled && var.canary_mode ?
    toset([data.aws_caller_identity.current.account_id]) :
    var.authorized_account_ids
  )
  effective_allowed_target_cidrs = (
    var.managed_canary_enabled && var.canary_mode ?
    toset([module.managed_canary[0].public_cidr]) :
    var.allowed_target_cidrs
  )
  effective_allowed_tag_keys = setunion(
    var.allowed_tag_keys,
    var.managed_canary_enabled ? toset(["service"]) : toset([])
  )
  effective_allowed_eni_interface_types = (
    var.managed_canary_enabled && var.canary_mode ?
    toset(["interface"]) :
    var.inventory_allowed_eni_interface_types
  )
  effective_required_target_tag_key = (
    var.managed_canary_enabled && var.canary_mode ?
    module.managed_canary[0].inventory_tag_key :
    var.inventory_required_target_tag_key
  )
  effective_required_target_tag_value = (
    var.managed_canary_enabled && var.canary_mode ?
    module.managed_canary[0].inventory_tag_value :
    var.inventory_required_target_tag_value
  )
}

resource "terraform_data" "deployment_stage_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition = !var.deploy_runtime || alltrue([
        for image in local.required_images :
        can(regex("^sha256:[0-9a-f]{64}$", var.image_digests[image]))
      ])
      error_message = "deploy_runtime requires all seven externally built image digests."
    }

    precondition {
      condition     = !var.run_migration || (var.deploy_runtime && can(regex("^[0-9a-f]{64}$", var.migration_checksum)))
      error_message = "run_migration requires deploy_runtime and a lowercase SHA-256 migration checksum."
    }

    precondition {
      condition = !var.install_operator || (
        var.deploy_runtime &&
        var.run_migration &&
        length(var.eks_installer_principal_arns) > 0 &&
        (
          length(var.eks_api_client_security_group_ids) > 0 ||
          (var.eks_endpoint_public_access && length(var.eks_public_access_cidrs) > 0)
        )
      )
      error_message = "install_operator requires runtime, migration, an explicit EKS installer principal, and either an approved private API client security group or an explicitly restricted public endpoint."
    }

    precondition {
      condition = (
        var.eks_endpoint_public_access && length(var.eks_public_access_cidrs) > 0
        ) || (
        !var.eks_endpoint_public_access && length(var.eks_public_access_cidrs) == 0
      )
      error_message = "Public EKS API access requires at least one restricted CIDR, and eks_public_access_cidrs must be empty when public access is disabled."
    }

    precondition {
      condition = (
        var.lambda_architecture == "arm64" &&
        var.node_ami_type == "AL2023_ARM_64_STANDARD"
        ) || (
        var.lambda_architecture == "x86_64" &&
        var.node_ami_type == "AL2023_x86_64_STANDARD"
      )
      error_message = "Lambda image architecture and EKS node AMI architecture must match."
    }

    precondition {
      condition = !var.enable_event_dispatch || (
        var.deploy_runtime &&
        var.run_migration &&
        var.install_operator &&
        length(local.effective_authorized_account_ids) > 0
      )
      error_message = "Activation requires runtime, migration, operator installation, and explicit authorized_account_ids."
    }

    precondition {
      condition = !(
        local.periodic_snapshots_enabled ||
        local.periodic_coverage_enabled ||
        local.signal_hints_enabled
      ) || var.enable_event_dispatch
      error_message = "Periodic snapshots, coverage, and signal hints require the queue and stream dispatch pipeline."
    }

    precondition {
      condition = !local.processor_reconciliation_enabled || (
        var.deploy_runtime && var.run_migration
      )
      error_message = "Processor reconciliation requires deployed, migrated runtime."
    }

    precondition {
      condition = !var.canary_mode || (
        var.deploy_runtime &&
        var.run_migration &&
        var.install_operator &&
        !local.periodic_snapshots_enabled &&
        !local.periodic_coverage_enabled &&
        !local.signal_hints_enabled &&
        length(local.effective_authorized_account_ids) > 0 &&
        length(local.effective_allowed_target_cidrs) == 1 &&
        can(regex("/32$", try(one(local.effective_allowed_target_cidrs), "")))
      )
      error_message = "canary_mode requires installed migrated runtime, explicit account scope, one exact /32 target allowlist, and automatic inventory disabled."
    }

    precondition {
      condition = !var.managed_canary_enabled || (
        length(local.managed_canary_scanner_source_cidrs) > 0
      )
      error_message = "managed_canary_enabled requires at least one scanner NAT EIP."
    }

    precondition {
      condition = !(var.managed_canary_enabled && var.canary_mode) ? true : alltrue([
        for cidr in var.denied_target_cidrs :
        cidrhost(
          "${module.managed_canary[0].public_ip}/${split("/", cidr)[1]}",
          0
        ) != split("/", cidr)[0]
      ])
      error_message = "The managed canary EIP must not be included by denied_target_cidrs."
    }

    precondition {
      condition = (
        var.inventory_required_target_tag_key == null &&
        var.inventory_required_target_tag_value == null
        ) || (
        try(length(var.inventory_required_target_tag_key) > 0, false) &&
        try(length(var.inventory_required_target_tag_value) > 0, false)
      )
      error_message = "inventory_required_target_tag_key and inventory_required_target_tag_value must be configured together."
    }
  }
}

resource "terraform_data" "authorized_scope_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition = alltrue([
        for account_id in setunion(var.allowed_member_account_ids, var.authorized_account_ids) :
        can(regex("^[0-9]{12}$", account_id))
      ])
      error_message = "Account authorization scopes must contain only 12-digit account IDs."
    }

    precondition {
      condition = !(
        local.periodic_snapshots_enabled || local.signal_hints_enabled
        ) || var.allowed_organization_id != null || alltrue([
          for account_id in local.effective_authorized_account_ids :
          contains(local.bus_authorized_account_ids, account_id)
      ])
      error_message = "Every activated account scope must be the local account or an account authorized by the central bus."
    }

    precondition {
      condition     = length(var.allowed_member_account_ids) == 0 || var.create_central_event_bus
      error_message = "Member account authorization requires create_central_event_bus."
    }

    precondition {
      condition = alltrue([
        for account_id, role_arn in var.member_collector_role_arns :
        can(regex("^[0-9]{12}$", account_id)) &&
        can(regex("^arn:[^:]+:iam::${account_id}:role/.+$", role_arn)) &&
        contains(var.authorized_account_ids, account_id)
      ])
      error_message = "Each member collector role must match its authorized 12-digit account key."
    }

    precondition {
      condition = (
        toset(keys(var.member_collector_role_arns)) == toset(keys(var.member_collector_external_ids)) &&
        alltrue([
          for external_id in values(var.member_collector_external_ids) :
          length(external_id) >= 16
        ])
      )
      error_message = "Every member collector role requires a paired external ID of at least 16 characters."
    }
  }
}

module "network" {
  source = "../modules/network"

  name_prefix                                            = local.name
  create_vpc                                             = var.create_vpc
  vpc_cidr                                               = var.vpc_cidr
  az_count                                               = var.az_count
  availability_zones                                     = var.availability_zones
  nat_gateway_mode                                       = var.nat_gateway_mode
  existing_vpc_id                                        = var.existing_vpc_id
  existing_public_subnet_ids                             = var.existing_public_subnet_ids
  existing_private_subnet_ids                            = var.existing_private_subnet_ids
  existing_isolated_subnet_ids                           = var.existing_isolated_subnet_ids
  existing_private_subnet_egress_mode                    = var.existing_private_subnet_egress_mode
  existing_public_nat_gateway_ids                        = var.existing_public_nat_gateway_ids
  existing_transit_gateway_public_egress_acknowledged    = var.existing_transit_gateway_public_egress_acknowledged
  existing_private_vpc_endpoint_ids                      = var.existing_private_vpc_endpoint_ids
  existing_private_interface_endpoint_security_group_ids = var.existing_private_interface_endpoint_security_group_ids
  scanner_public_egress_required                         = var.enable_event_dispatch
}

module "managed_canary" {
  count  = var.managed_canary_enabled ? 1 : 0
  source = "../modules/managed-canary"

  name_prefix               = local.name
  vpc_cidr                  = var.managed_canary_vpc_cidr
  scanner_source_ipv4_cidrs = local.managed_canary_scanner_source_cidrs
  instance_type             = var.managed_canary_instance_type
  listener_port             = 18080
}

module "storage" {
  source = "../modules/storage"

  name_prefix                       = local.name
  lambda_timeout_seconds            = var.lambda_timeout_seconds
  queue_visibility_timeout_seconds  = var.queue_visibility_timeout_seconds
  queue_retention_seconds           = var.queue_retention_seconds
  queue_age_alarm_threshold_seconds = var.queue_age_alarm_threshold_seconds
  alarm_action_arns                 = var.alarm_action_arns
  ok_action_arns                    = var.ok_action_arns
  bucket_expiration_days            = var.bucket_expiration_days
  force_destroy_buckets             = var.force_destroy_buckets
  dynamodb_point_in_time_recovery   = var.dynamodb_point_in_time_recovery
  cloudtrail_source_arns            = var.cloudtrail_mode == "create" ? compact([local.cloudtrail_arn]) : []
  enable_config_delivery            = var.config_mode == "create"
  finding_export_enabled            = var.finding_export_enabled
  enable_cloudtrail_storage         = var.cloudtrail_mode == "create"
  signal_event_rule_arns            = local.signal_rule_arns
}

module "repositories" {
  source = "../modules/repositories"

  name_prefix                    = local.name
  untagged_image_expiration_days = var.ecr_untagged_image_expiration_days
  force_delete                   = var.force_delete_repositories
}

module "database" {
  source = "../modules/database"

  name_prefix                   = local.name
  vpc_id                        = module.network.vpc_id
  isolated_subnet_ids           = module.network.isolated_subnet_ids
  application_security_group_id = module.network.lambda_database_security_group_id
  database_name                 = var.database_name
  engine_version                = var.database_engine_version
  instance_class                = var.database_instance_class
  instance_count                = var.database_instance_count
  backup_retention_days         = var.database_backup_retention_days
  deletion_protection           = var.database_deletion_protection
  skip_final_snapshot           = var.database_skip_final_snapshot
  final_snapshot_identifier     = var.database_final_snapshot_identifier
  apply_immediately             = var.database_apply_immediately
}

module "signals" {
  source = "../modules/signals"

  name_prefix                     = local.name
  signal_queue_arn                = module.storage.queue_arns["signal"]
  signal_dead_letter_queue_arn    = module.storage.dead_letter_queue_arns["signal"]
  enable_event_dispatch           = local.signal_hints_enabled
  config_mode                     = var.config_mode
  config_delivery_bucket_name     = module.storage.bucket_names["events"]
  existing_config_aggregator_name = var.existing_config_aggregator_name
  cloudtrail_mode                 = var.cloudtrail_mode
  existing_cloudtrail_arn         = var.existing_cloudtrail_arn
  cloudtrail_name                 = local.cloudtrail_name
  cloudtrail_bucket_name          = try(module.storage.bucket_names["cloudtrail"], null)
  create_central_event_bus        = var.create_central_event_bus
  allowed_member_account_ids      = var.allowed_member_account_ids
  allowed_organization_id         = var.allowed_organization_id
  authorized_account_ids          = local.effective_authorized_account_ids
  config_aggregator_account_ids   = local.effective_authorized_account_ids

  depends_on = [module.storage]
}

module "identities" {
  source = "../modules/identities"

  name_prefix                     = local.name
  bucket_arns                     = module.storage.bucket_arns
  queue_arns                      = module.storage.queue_arns
  table_arns                      = module.storage.table_arns
  table_stream_arns               = module.storage.table_stream_arns
  database_master_secret_arn      = module.database.master_secret_arn
  database_application_secret_arn = module.database.application_secret_arn
  eks_cluster_arn                 = local.eks_cluster_arn
  member_collector_role_arns      = values(var.member_collector_role_arns)
  target_event_object_prefix      = "target-events/aws/"
  finding_export_enabled          = var.finding_export_enabled
}

module "functions" {
  source = "../modules/functions"

  name_prefix                          = local.name
  deploy_runtime                       = var.deploy_runtime
  run_migration                        = var.run_migration
  enable_event_dispatch                = var.enable_event_dispatch
  periodic_snapshots_enabled           = local.periodic_snapshots_enabled
  periodic_coverage_enabled            = local.periodic_coverage_enabled
  signal_hints_enabled                 = local.signal_hints_enabled
  processor_reconciliation_enabled     = local.processor_reconciliation_enabled
  finding_export_enabled               = var.finding_export_enabled
  canary_mode                          = var.canary_mode
  image_digests                        = var.image_digests
  repository_urls                      = module.repositories.repository_urls
  function_role_arns                   = module.identities.function_role_arns
  private_subnet_ids                   = module.network.private_subnet_ids
  security_group_id                    = module.network.lambda_runtime_security_group_id
  database_security_group_id           = module.network.lambda_database_security_group_id
  queue_urls                           = module.storage.queue_urls
  queue_arns                           = module.storage.queue_arns
  table_names                          = module.storage.table_names
  table_stream_arns                    = module.storage.table_stream_arns
  bucket_names                         = module.storage.bucket_names
  database_name                        = module.database.database_name
  database_master_secret_arn           = module.database.master_secret_arn
  database_application_secret_arn      = module.database.application_secret_arn
  database_application_username        = var.database_application_username
  config_aggregator_name               = module.signals.config_aggregator_name
  snapshot_backend                     = local.snapshot_backend
  snapshot_account_id                  = data.aws_caller_identity.current.account_id
  snapshot_regions                     = local.snapshot_regions
  allowed_tag_keys                     = local.effective_allowed_tag_keys
  allowed_eni_interface_types          = local.effective_allowed_eni_interface_types
  required_target_tag_key              = local.effective_required_target_tag_key
  required_target_tag_value            = local.effective_required_target_tag_value
  snapshot_max_pages                   = var.snapshot_max_pages
  managed_canary                       = local.managed_canary
  allowed_target_cidrs                 = local.effective_allowed_target_cidrs
  denied_target_cidrs                  = var.denied_target_cidrs
  target_event_prefix                  = "target-events/aws"
  authorized_account_ids               = local.effective_authorized_account_ids
  member_collector_role_arns           = var.member_collector_role_arns
  member_collector_external_ids        = var.member_collector_external_ids
  eks_cluster_name                     = local.cluster_name
  eks_namespace                        = var.eks_namespace
  lambda_timeout_seconds               = var.lambda_timeout_seconds
  memory_size_mb                       = var.lambda_memory_size_mb
  architecture                         = var.lambda_architecture
  log_retention_days                   = var.lambda_log_retention_days
  iterator_age_alarm_threshold_seconds = var.iterator_age_alarm_threshold_seconds
  alarm_action_arns                    = var.alarm_action_arns
  ok_action_arns                       = var.ok_action_arns
  reserved_concurrency                 = var.lambda_reserved_concurrency
  snapshot_schedule_expression         = var.snapshot_schedule_expression
  rescan_schedule_expression           = var.rescan_schedule_expression
  processor_schedule_expression        = var.processor_schedule_expression
  migration_checksum                   = var.migration_checksum
}

module "eks" {
  source = "../modules/eks"

  name_prefix                                    = local.cluster_name
  private_subnet_ids                             = module.network.private_subnet_ids
  kubernetes_version                             = var.kubernetes_version
  node_instance_types                            = var.node_instance_types
  node_ami_type                                  = var.node_ami_type
  node_capacity_type                             = var.node_capacity_type
  node_desired_size                              = var.node_desired_size
  node_min_size                                  = var.node_min_size
  node_max_size                                  = var.node_max_size
  node_disk_size_gib                             = var.node_disk_size_gib
  bootstrap_cluster_creator_admin_permissions    = var.bootstrap_cluster_creator_admin_permissions
  generator_role_arn                             = module.identities.generator_role_arn
  generator_security_group_id                    = module.network.lambda_runtime_security_group_id
  additional_api_client_security_group_ids       = var.eks_api_client_security_group_ids
  endpoint_public_access                         = var.eks_endpoint_public_access
  public_access_cidrs                            = var.eks_public_access_cidrs
  existing_interface_endpoint_security_group_ids = module.network.existing_interface_endpoint_security_group_ids
  installer_principal_arns                       = var.eks_installer_principal_arns
  scanner_pod_role_arn                           = module.identities.scanner_pod_role_arn
  allowed_target_cidrs                           = local.effective_allowed_target_cidrs
  denied_target_cidrs                            = var.denied_target_cidrs
  operator_max_concurrent_reconciles             = var.operator_max_concurrent_reconciles
  scanner_max_concurrent_pods                    = var.scanner_max_concurrent_pods
  scanner_max_jobs                               = var.scanner_max_jobs
  scanner_min_rate                               = var.scanner_min_rate
  scanner_max_rate                               = var.scanner_max_rate
  namespace                                      = var.eks_namespace
  chart_path                                     = local.operator_chart_path
  install_operator                               = var.install_operator
  repository_urls                                = module.repositories.repository_urls
  image_digests                                  = var.image_digests
  migration_token                                = module.functions.migration_token
  workload_architecture                          = var.lambda_architecture
  results_bucket_name                            = module.storage.bucket_names["results"]
}
