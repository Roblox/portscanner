output "vpc_id" {
  value = module.portscanner.vpc_id
}

output "private_subnet_ids" {
  value = module.portscanner.private_subnet_ids
}

output "isolated_subnet_ids" {
  value = module.portscanner.isolated_subnet_ids
}

output "scanner_egress_public_ips" {
  value = module.portscanner.scanner_egress_public_ips
}

output "bucket_names" {
  value = module.portscanner.bucket_names
}

output "bucket_arns" {
  value = module.portscanner.bucket_arns
}

output "queue_urls" {
  value = module.portscanner.queue_urls
}

output "queue_arns" {
  value = module.portscanner.queue_arns
}

output "dead_letter_queue_arns" {
  value = module.portscanner.dead_letter_queue_arns
}

output "table_names" {
  value = module.portscanner.table_names
}

output "inventory_table_name" {
  value = module.portscanner.inventory_table_name
}

output "dispatch_table_name" {
  value = module.portscanner.dispatch_table_name
}

output "target_event_queue_url" {
  value = module.portscanner.target_event_queue_url
}

output "finding_queue_url" {
  value = module.portscanner.finding_queue_url
}

output "finding_queue_arn" {
  value = module.portscanner.finding_queue_arn
}

output "finding_bucket_name" {
  value = module.portscanner.finding_bucket_name
}

output "finding_bucket_arn" {
  value = module.portscanner.finding_bucket_arn
}

output "repository_urls" {
  value = module.portscanner.repository_urls
}

output "database_cluster_endpoint" {
  value = module.portscanner.database_cluster_endpoint
}

output "database_master_secret_arn" {
  value     = module.portscanner.database_master_secret_arn
  sensitive = true
}

output "database_application_secret_arn" {
  value = module.portscanner.database_application_secret_arn
}

output "eks_cluster_name" {
  value = module.portscanner.eks_cluster_name
}

output "eks_cluster_endpoint" {
  value = module.portscanner.eks_cluster_endpoint
}

output "central_event_bus_arn" {
  value = module.portscanner.central_event_bus_arn
}

output "config_aggregator_name" {
  value = module.portscanner.config_aggregator_name
}

output "cloudtrail_arn" {
  value = module.portscanner.cloudtrail_arn
}

output "signal_region" {
  value = module.portscanner.signal_region
}

output "created_config_source_regions" {
  value = module.portscanner.created_config_source_regions
}

output "function_arns" {
  value = module.portscanner.function_arns
}

output "managed_canary" {
  value = module.portscanner.managed_canary
}

output "managed_canary_snapshot_invocation" {
  value = module.portscanner.managed_canary_snapshot_invocation
}

output "managed_canary_status_invocation" {
  value = module.portscanner.managed_canary_status_invocation
}

output "operator_namespace" {
  value = module.portscanner.operator_namespace
}

output "retirement_configuration_fingerprint" {
  description = "Stable when managed_canary.enabled is the only environment change."
  value       = local.retirement_configuration_fingerprint
}

output "emergency_pause_controls" {
  value = module.portscanner.emergency_pause_controls
}

output "alarm_names" {
  value = module.portscanner.alarm_names
}

output "alarm_arns" {
  value = module.portscanner.alarm_arns
}

output "central_collector_principal_arn" {
  value = module.portscanner.central_collector_principal_arn
}

output "central_collector_principal_arns" {
  value = module.portscanner.central_collector_principal_arns
}

output "deployment_state" {
  value = module.portscanner.deployment_state
}

output "workload_architecture" {
  value = module.portscanner.workload_architecture
}
