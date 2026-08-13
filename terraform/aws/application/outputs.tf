output "vpc_id" {
  value = module.network.vpc_id
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "isolated_subnet_ids" {
  value = module.network.isolated_subnet_ids
}

output "scanner_egress_public_ips" {
  description = "Created-VPC NAT addresses from which scanner traffic exits. Empty when existing networking owns egress."
  value       = module.network.created_nat_public_ips
}

output "bucket_names" {
  value = module.storage.bucket_names
}

output "bucket_arns" {
  value = module.storage.bucket_arns
}

output "queue_urls" {
  value = module.storage.queue_urls
}

output "queue_arns" {
  value = module.storage.queue_arns
}

output "dead_letter_queue_arns" {
  value = module.storage.dead_letter_queue_arns
}

output "table_names" {
  value = module.storage.table_names
}

output "inventory_table_name" {
  description = "Single-table inventory state, outbox, and signal-dedupe store."
  value       = module.storage.table_names["inventory"]
}

output "dispatch_table_name" {
  description = "Generator idempotency and dispatch-audit table."
  value       = module.storage.table_names["dispatch"]
}

output "target_event_queue_url" {
  description = "Target projector handoff queue."
  value       = module.storage.queue_urls["target-event"]
}

output "finding_queue_url" {
  description = "External finding handoff notification queue; no in-stack Lambda consumes it."
  value       = module.storage.finding_queue_url
}

output "finding_queue_arn" {
  description = "ARN of the external finding handoff queue for consumer IAM policies."
  value       = module.storage.finding_queue_arn
}

output "finding_bucket_name" {
  description = "Bucket containing immutable finding documents referenced by finding queue notifications."
  value       = module.storage.finding_bucket_name
}

output "finding_bucket_arn" {
  description = "ARN of the immutable finding bucket for consumer IAM policies."
  value       = module.storage.finding_bucket_arn
}

output "repository_urls" {
  description = "Push externally built images here, then pass immutable sha256 digests back as image_digests."
  value       = module.repositories.repository_urls
}

output "database_cluster_endpoint" {
  value = module.database.cluster_endpoint
}

output "database_master_secret_arn" {
  value     = module.database.master_secret_arn
  sensitive = true
}

output "database_application_secret_arn" {
  description = "Created empty; the keyed migrator initializes the application credential without storing it in Terraform state."
  value       = module.database.application_secret_arn
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "central_event_bus_arn" {
  value = module.signals.central_event_bus_arn
}

output "config_aggregator_name" {
  value = module.signals.config_aggregator_name
}

output "cloudtrail_arn" {
  value = module.signals.cloudtrail_arn
}

output "signal_region" {
  description = "Region containing this root's local EventBridge rules and central bus."
  value       = module.signals.signal_region
}

output "created_config_source_regions" {
  description = "Explicit source Regions for a created Config aggregator."
  value       = module.signals.created_config_source_regions
}

output "function_arns" {
  value = module.functions.function_arns
}

output "managed_canary" {
  description = "Terraform-owned target identity and lifecycle-relevant values. Null when disabled."
  value = var.managed_canary_enabled ? {
    account_id           = data.aws_caller_identity.current.account_id
    region               = data.aws_region.current.region
    vpc_id               = module.managed_canary[0].vpc_id
    subnet_id            = module.managed_canary[0].subnet_id
    security_group_id    = module.managed_canary[0].security_group_id
    eip_allocation_id    = module.managed_canary[0].eip_allocation_id
    public_ip            = module.managed_canary[0].public_ip
    public_cidr          = module.managed_canary[0].public_cidr
    network_interface_id = module.managed_canary[0].network_interface_id
    private_ip           = module.managed_canary[0].private_ip
    instance_id          = module.managed_canary[0].instance_id
    instance_state       = module.managed_canary[0].instance_state
    listener_port        = module.managed_canary[0].listener_port
    inventory_tag_key    = module.managed_canary[0].inventory_tag_key
    inventory_tag_value  = module.managed_canary[0].inventory_tag_value
  } : null
}

output "managed_canary_eip_allocation_id" {
  value = var.managed_canary_enabled ? module.managed_canary[0].eip_allocation_id : null
}

output "managed_canary_public_ip" {
  value = var.managed_canary_enabled ? module.managed_canary[0].public_ip : null
}

output "managed_canary_public_cidr" {
  value = var.managed_canary_enabled ? module.managed_canary[0].public_cidr : null
}

output "managed_canary_network_interface_id" {
  value = var.managed_canary_enabled ? module.managed_canary[0].network_interface_id : null
}

output "managed_canary_instance_id" {
  value = var.managed_canary_enabled ? module.managed_canary[0].instance_id : null
}

output "managed_canary_listener_port" {
  value = var.managed_canary_enabled ? module.managed_canary[0].listener_port : null
}

output "managed_canary_snapshot_function_name" {
  value = var.managed_canary_enabled ? module.functions.snapshot_function_name : null
}

output "managed_canary_snapshot_function_arn" {
  value = var.managed_canary_enabled ? module.functions.snapshot_function_arn : null
}

output "managed_canary_status_function_name" {
  value = var.managed_canary_enabled ? module.functions.processor_function_name : null
}

output "managed_canary_status_function_arn" {
  value = var.managed_canary_enabled ? module.functions.processor_function_arn : null
}

output "managed_canary_snapshot_invocation" {
  description = "Narrow payload and function used by deployment automation for the one-target inventory invocation."
  value = var.managed_canary_enabled ? {
    function_name = module.functions.snapshot_function_name
    function_arn  = module.functions.snapshot_function_arn
    payload = {
      operation = "managed-canary"
    }
  } : null
}

output "managed_canary_status_invocation" {
  description = "Narrow processor status operation for deployment automation."
  value = var.managed_canary_enabled ? {
    function_name = module.functions.processor_function_name
    function_arn  = module.functions.processor_function_arn
    payload = {
      operation = "managed-canary-status"
    }
  } : null
}

output "operator_namespace" {
  description = "Namespace containing the Helm release and scanner Jobs."
  value       = var.eks_namespace
}

output "emergency_pause_controls" {
  description = "Exact AWS-side dispatch controls used by emergency-pause.sh without refreshing Helm or EKS."
  value = {
    account_id                 = data.aws_caller_identity.current.account_id
    region                     = data.aws_region.current.region
    event_source_mapping_uuids = sort(module.functions.event_source_mapping_uuids)
    event_rule_controls = concat(
      module.functions.schedule_rule_controls,
      module.signals.signal_rule_controls
    )
  }
}

output "alarm_names" {
  description = "CloudWatch alarm names grouped by storage and Lambda runtime."
  value = {
    storage   = module.storage.alarm_names
    functions = module.functions.alarm_names
  }
}

output "alarm_arns" {
  description = "CloudWatch alarm ARNs grouped by storage and Lambda runtime."
  value = {
    storage   = module.storage.alarm_arns
    functions = module.functions.alarm_arns
  }
}

output "central_collector_principal_arn" {
  description = "Exact snapshot Lambda role ARN retained for snapshot-only member trust."
  value       = module.identities.snapshot_role_arn
}

output "central_collector_principal_arns" {
  description = "Exact snapshot and signal Lambda role ARNs for member collector trust."
  value = [
    module.identities.snapshot_role_arn,
    module.identities.signals_role_arn
  ]
}

output "deployment_state" {
  value = {
    runtime_created    = var.deploy_runtime
    migration_run      = var.run_migration
    operator_installed = var.install_operator
    dispatch_enabled   = var.enable_event_dispatch
    automatic_inventory_enabled = (
      local.periodic_snapshots_enabled ||
      local.periodic_coverage_enabled ||
      local.signal_hints_enabled ||
      local.processor_reconciliation_enabled
    )
    periodic_snapshots_enabled       = local.periodic_snapshots_enabled
    periodic_coverage_enabled        = local.periodic_coverage_enabled
    signal_hints_enabled             = local.signal_hints_enabled
    processor_reconciliation_enabled = local.processor_reconciliation_enabled
    finding_export_enabled           = var.finding_export_enabled
    managed_canary_enabled           = var.managed_canary_enabled
    canary_mode                      = var.canary_mode
  }
}

output "workload_architecture" {
  description = "Applied Lambda and EKS architecture contract required by image publication."
  value = {
    architecture        = var.lambda_architecture
    node_ami_type       = var.node_ami_type
    node_instance_types = var.node_instance_types
  }
}
