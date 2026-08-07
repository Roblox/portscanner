output "vpc_id" {
  value = module.network.vpc_id
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "isolated_subnet_ids" {
  value = module.network.isolated_subnet_ids
}

output "bucket_names" {
  value = module.storage.bucket_names
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
  value       = module.storage.queue_urls["finding"]
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

output "function_arns" {
  value = module.functions.function_arns
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
  }
}
