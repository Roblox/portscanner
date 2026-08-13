variable "name_prefix" {
  description = "Portable lowercase prefix. No organization-specific name is assumed."
  type        = string
  default     = "portscanner"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 lowercase alphanumeric or hyphen characters."
  }
}

variable "create_vpc" {
  description = "Create a three-tier VPC or use validated existing networking."
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR used only when create_vpc is true."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Optional explicit availability zones for a created VPC."
  type        = list(string)
  default     = null
}

variable "az_count" {
  description = "Availability-zone count for a created VPC."
  type        = number
  default     = 2
}

variable "nat_gateway_mode" {
  description = "single is economical; one_per_az is the production resilience override."
  type        = string
  default     = "single"
}

variable "existing_vpc_id" {
  description = "Existing VPC ID when create_vpc is false."
  type        = string
  default     = null
}

variable "existing_public_subnet_ids" {
  description = "Optional existing public subnet IDs; workloads never use them."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_ids" {
  description = "Existing private EKS/Lambda subnet IDs."
  type        = list(string)
  default     = []
}

variable "existing_isolated_subnet_ids" {
  description = "Existing isolated Aurora subnet IDs."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_egress_mode" {
  description = "Required existing-VPC egress declaration: nat_gateway, transit_gateway, or vpc_endpoints."
  type        = string
  default     = null

  validation {
    condition = var.existing_private_subnet_egress_mode == null ? true : contains(
      ["nat_gateway", "transit_gateway", "vpc_endpoints"],
      var.existing_private_subnet_egress_mode
    )
    error_message = "existing_private_subnet_egress_mode must be null, nat_gateway, transit_gateway, or vpc_endpoints."
  }
}

variable "existing_public_nat_gateway_ids" {
  description = "Public NAT gateway IDs used by every scanner subnet default route when existing-VPC dispatch is enabled."
  type        = set(string)
  default     = []
}

variable "existing_transit_gateway_public_egress_acknowledged" {
  description = "Explicit reviewed acknowledgement that the TGW default routes are active/non-blackhole and reach public scanner egress."
  type        = bool
  default     = false
}

variable "existing_private_vpc_endpoint_ids" {
  description = "Existing VPC endpoint IDs keyed by required AWS service when egress mode is vpc_endpoints."
  type        = map(string)
  default     = {}
}

variable "existing_private_interface_endpoint_security_group_ids" {
  description = "One attached security group per required interface endpoint, keyed by service; Terraform manages workload TLS ingress."
  type        = map(string)
  default     = {}
}

variable "managed_canary_enabled" {
  description = "Provision the isolated Terraform-owned TCP 18080 evaluation target. Advanced roots default to disabled."
  type        = bool
  default     = false
}

variable "managed_canary_vpc_cidr" {
  description = "Dedicated unpeered managed-canary VPC /28."
  type        = string
  default     = "10.255.255.0/28"
}

variable "managed_canary_instance_type" {
  description = "Tiny ARM EC2 instance type for the managed canary."
  type        = string
  default     = "t4g.nano"
}

variable "managed_canary_scanner_source_ipv4s" {
  description = "Scanner egress EIPs for existing/TGW networking; created-VPC NAT EIPs are derived automatically."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for address in var.managed_canary_scanner_source_ipv4s :
      can(cidrnetmask("${address}/32")) &&
      try(cidrhost("${address}/32", 0) == address, false)
    ])
    error_message = "managed_canary_scanner_source_ipv4s must contain canonical IPv4 addresses."
  }
}

variable "lambda_timeout_seconds" {
  description = "Timeout for queue-triggered Lambda functions."
  type        = number
  default     = 60
}

variable "queue_visibility_timeout_seconds" {
  description = "Must be at least six times lambda_timeout_seconds for Lambda SQS event sources."
  type        = number
  default     = 360
}

variable "queue_retention_seconds" {
  description = "Primary SQS message retention."
  type        = number
  default     = 345600
}

variable "queue_age_alarm_threshold_seconds" {
  description = "Oldest-message age that alarms every primary SQS queue."
  type        = number
  default     = 900

  validation {
    condition     = var.queue_age_alarm_threshold_seconds >= 60 && var.queue_age_alarm_threshold_seconds <= 1209600
    error_message = "queue_age_alarm_threshold_seconds must be between 60 and 1209600."
  }
}

variable "iterator_age_alarm_threshold_seconds" {
  description = "Maximum inventory outbox stream iterator age before alarming."
  type        = number
  default     = 900

  validation {
    condition     = var.iterator_age_alarm_threshold_seconds >= 60 && var.iterator_age_alarm_threshold_seconds <= 1209600
    error_message = "iterator_age_alarm_threshold_seconds must be between 60 and 1209600."
  }
}

variable "alarm_action_arns" {
  description = "Existing CloudWatch alarm action ARNs. Empty creates alarms without notification integrations."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.alarm_action_arns :
      can(regex("^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$", arn))
    ])
    error_message = "alarm_action_arns must contain valid ARN-shaped values."
  }
}

variable "ok_action_arns" {
  description = "Existing action ARNs invoked when CloudWatch alarms return to OK."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.ok_action_arns :
      can(regex("^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$", arn))
    ])
    error_message = "ok_action_arns must contain valid ARN-shaped values."
  }
}

variable "dynamodb_point_in_time_recovery" {
  description = "Enable DynamoDB PITR. Production should set this true."
  type        = bool
  default     = false
}

variable "bucket_expiration_days" {
  description = "Lifecycle expiration by data purpose."
  type        = map(number)
  default = {
    events     = 30
    results    = 90
    findings   = 365
    cloudtrail = 365
  }
}

variable "force_destroy_buckets" {
  description = "Delete all object versions on destroy. Enable only for disposable sandboxes."
  type        = bool
  default     = false
}

variable "force_delete_repositories" {
  description = "Delete ECR images with repositories during destroy. Enable only for disposable sandboxes."
  type        = bool
  default     = false
}

variable "ecr_untagged_image_expiration_days" {
  description = "Optional age for expiring only untagged ECR images. Null disables ECR lifecycle expiration."
  type        = number
  default     = null

  validation {
    condition     = var.ecr_untagged_image_expiration_days == null ? true : var.ecr_untagged_image_expiration_days >= 1
    error_message = "ecr_untagged_image_expiration_days must be null or positive."
  }
}

variable "database_name" {
  description = "Initial Aurora database."
  type        = string
  default     = "portscanner"
}

variable "database_engine_version" {
  description = "Supported Aurora PostgreSQL version in the target region."
  type        = string
  default     = "16.4"
}

variable "database_instance_class" {
  description = "Aurora instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "database_instance_count" {
  description = "One is a development default; production should use at least two."
  type        = number
  default     = 1
}

variable "database_backup_retention_days" {
  description = "Aurora backup retention."
  type        = number
  default     = 7
}

variable "database_deletion_protection" {
  description = "Production should set this true."
  type        = bool
  default     = false
}

variable "database_skip_final_snapshot" {
  description = "Development default; production should set false."
  type        = bool
  default     = true
}

variable "database_final_snapshot_identifier" {
  description = "Required when database_skip_final_snapshot is false."
  type        = string
  default     = null
}

variable "database_apply_immediately" {
  description = "Apply Aurora modifications immediately."
  type        = bool
  default     = false
}

variable "database_application_username" {
  description = "Least-privilege PostgreSQL username created by the migrator."
  type        = string
  default     = "portscanner_app"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_]{0,62}$", var.database_application_username))
    error_message = "database_application_username must be a valid lowercase PostgreSQL identifier."
  }
}

variable "config_mode" {
  description = "create, existing, or disabled."
  type        = string
  default     = "create"

  validation {
    condition     = contains(["create", "existing", "disabled"], var.config_mode)
    error_message = "config_mode must be create, existing, or disabled."
  }
}

variable "existing_config_aggregator_name" {
  description = "Existing aggregator name when config_mode is existing."
  type        = string
  default     = null
}

variable "snapshot_regions" {
  description = "Regions queried by direct EC2 snapshots when Config is disabled; empty uses the deployment region."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for region in var.snapshot_regions :
      can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", region))
    ])
    error_message = "snapshot_regions must contain valid AWS region names."
  }
}

variable "allowed_tag_keys" {
  description = "AWS tags permitted in target context; keys must be part of the shared contract."
  type        = set(string)
  default     = ["application", "environment", "name", "service"]

  validation {
    condition = length(setsubtract(
      var.allowed_tag_keys,
      toset(["application", "environment", "name", "service"])
    )) == 0
    error_message = "allowed_tag_keys contains a key outside the shared AWS contract."
  }
}

variable "inventory_allowed_eni_interface_types" {
  description = "Optional supported ENI classes. Empty disables the class gate for advanced-root compatibility."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for value in var.inventory_allowed_eni_interface_types :
      can(regex("^[a-z0-9-]+$", value))
    ])
    error_message = "inventory_allowed_eni_interface_types must contain lowercase AWS ENI class names."
  }
}

variable "inventory_required_target_tag_key" {
  description = "Optional exact ENI opt-in tag key paired with inventory_required_target_tag_value."
  type        = string
  default     = null
}

variable "inventory_required_target_tag_value" {
  description = "Optional exact ENI opt-in tag value paired with inventory_required_target_tag_key."
  type        = string
  default     = null
}

variable "snapshot_max_pages" {
  description = "Hard per-operation page bound for EC2 and Config snapshots."
  type        = number
  default     = 1000

  validation {
    condition     = var.snapshot_max_pages >= 1 && var.snapshot_max_pages <= 10000
    error_message = "snapshot_max_pages must be between 1 and 10000."
  }
}

variable "cloudtrail_mode" {
  description = "create, existing, or disabled. Disabled retains native EC2 state hints but omits local API-call hints."
  type        = string
  default     = "create"

  validation {
    condition     = contains(["create", "existing", "disabled"], var.cloudtrail_mode)
    error_message = "cloudtrail_mode must be create, existing, or disabled."
  }
}

variable "existing_cloudtrail_arn" {
  description = "Existing multi-region management trail ARN when cloudtrail_mode is existing."
  type        = string
  default     = null
}

variable "create_central_event_bus" {
  description = "Create a custom central bus for authorized member hints."
  type        = bool
  default     = true
}

variable "allowed_member_account_ids" {
  description = "Exact member accounts allowed by central event-bus policy."
  type        = set(string)
  default     = []
}

variable "allowed_organization_id" {
  description = "Optional organization condition in place of account principals. No Organizations lookup is performed."
  type        = string
  default     = null
}

variable "authorized_account_ids" {
  description = "Explicit inventory and dispatch scope. Activation fails if this scope is absent or unauthorized."
  type        = set(string)
  default     = []
}

variable "allowed_target_cidrs" {
  description = "Optional deployment-wide scanner allowlist of canonical IPv4 CIDRs. Empty leaves account ownership gates as the target scope."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.allowed_target_cidrs :
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "allowed_target_cidrs must contain only canonical IPv4 network prefixes."
  }
}

variable "denied_target_cidrs" {
  description = "Optional deployment-wide scanner denylist of canonical IPv4 CIDRs, enforced before the allowlist."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.denied_target_cidrs :
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "denied_target_cidrs must contain only canonical IPv4 network prefixes."
  }
}

variable "operator_max_concurrent_reconciles" {
  description = "Maximum concurrent Scanner reconciliations."
  type        = number
  default     = 4

  validation {
    condition     = var.operator_max_concurrent_reconciles >= 1 && var.operator_max_concurrent_reconciles <= 32 && floor(var.operator_max_concurrent_reconciles) == var.operator_max_concurrent_reconciles
    error_message = "operator_max_concurrent_reconciles must be an integer between 1 and 32."
  }
}

variable "scanner_max_concurrent_pods" {
  description = "Hard cap on simultaneously active scanner Pods across scanner priority classes."
  type        = number
  default     = 4

  validation {
    condition     = var.scanner_max_concurrent_pods >= 1 && var.scanner_max_concurrent_pods <= 100 && floor(var.scanner_max_concurrent_pods) == var.scanner_max_concurrent_pods
    error_message = "scanner_max_concurrent_pods must be an integer between 1 and 100."
  }
}

variable "scanner_max_jobs" {
  description = "Hard cap on active, pending, and retained scanner Job objects."
  type        = number
  default     = 16

  validation {
    condition     = var.scanner_max_jobs >= 1 && var.scanner_max_jobs <= 1000 && floor(var.scanner_max_jobs) == var.scanner_max_jobs
    error_message = "scanner_max_jobs must be an integer between 1 and 1000."
  }
}

variable "scanner_min_rate" {
  description = "Minimum Nmap probe rate passed to every scanner Job."
  type        = number
  default     = 100

  validation {
    condition     = var.scanner_min_rate >= 1 && var.scanner_min_rate <= 2000 && floor(var.scanner_min_rate) == var.scanner_min_rate
    error_message = "scanner_min_rate must be an integer between 1 and 2000."
  }
}

variable "scanner_max_rate" {
  description = "Maximum Nmap probe rate passed to every scanner Job."
  type        = number
  default     = 500

  validation {
    condition     = var.scanner_max_rate >= 1 && var.scanner_max_rate <= 5000 && floor(var.scanner_max_rate) == var.scanner_max_rate
    error_message = "scanner_max_rate must be an integer between 1 and 5000."
  }
}

variable "member_collector_role_arns" {
  description = "Exact member EC2 Describe-only collector role ARNs keyed by 12-digit account ID."
  type        = map(string)
  default     = {}
}

variable "member_collector_external_ids" {
  description = "External IDs paired with member_collector_role_arns by account ID."
  type        = map(string)
  default     = {}
}

variable "deploy_runtime" {
  description = "Create digest-pinned Lambda runtime. Event sources remain paused."
  type        = bool
  default     = false
}

variable "run_migration" {
  description = "Run the keyed aws_lambda_invocation migration."
  type        = bool
  default     = false
}

variable "install_operator" {
  description = "Install the namespace-scoped Helm operator after migration."
  type        = bool
  default     = false
}

variable "enable_event_dispatch" {
  description = "Enable the queue and stream pipeline after migration and operator installation."
  type        = bool
  default     = false
}

variable "periodic_snapshots_enabled" {
  description = "Enable authoritative periodic snapshots independently."
  type        = bool
  default     = false
}

variable "periodic_coverage_enabled" {
  description = "Enable recurring full-TCP coverage independently."
  type        = bool
  default     = false
}

variable "signal_hints_enabled" {
  description = "Enable EventBridge/CloudTrail signal intake independently."
  type        = bool
  default     = false
}

variable "processor_reconciliation_enabled" {
  description = "Enable scheduled PostgreSQL finding reconciliation independently."
  type        = bool
  default     = false
}

variable "finding_export_enabled" {
  description = "Create and publish optional S3/SQS finding handoffs. PostgreSQL is the default boundary."
  type        = bool
  default     = false
}

variable "canary_mode" {
  description = "Require one /32 target boundary while only the one-target dispatch pipeline is active."
  type        = bool
  default     = false
}

variable "image_digests" {
  description = "External image digests keyed by inventory, generator, parser, processor, migrator, operator, and scanner."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, digest in var.image_digests :
      contains(["inventory", "generator", "parser", "processor", "migrator", "operator", "scanner"], name) &&
      can(regex("^sha256:[0-9a-f]{64}$", digest))
    ])
    error_message = "Only supported image keys with sha256 digests are accepted."
  }
}

variable "migration_checksum" {
  description = "Lowercase SHA-256 checksum over ordered database migration content."
  type        = string
  default     = ""
}

variable "lambda_architecture" {
  description = "Architecture of externally built Lambda images."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.lambda_architecture)
    error_message = "lambda_architecture must be arm64 or x86_64."
  }
}

variable "lambda_memory_size_mb" {
  description = "Memory for ordinary Lambda functions."
  type        = number
  default     = 512
}

variable "lambda_log_retention_days" {
  description = "Lambda CloudWatch log retention."
  type        = number
  default     = 14
}

variable "lambda_reserved_concurrency" {
  description = "Conservative concurrency defaults; production throughput requires explicit tuning."
  type        = map(number)
  default = {
    snapshot           = 1
    signals            = 2
    outbox             = 2
    rescan             = 1
    generator_priority = 2
    generator_coverage = 1
    target_projector   = 2
    parser             = 2
    processor          = 2
    migrator           = 1
  }
}

variable "snapshot_schedule_expression" {
  description = "Authoritative snapshot reconciliation schedule."
  type        = string
  default     = "rate(5 minutes)"
}

variable "rescan_schedule_expression" {
  description = "Known-door full-coverage rescan schedule."
  type        = string
  default     = "rate(6 hours)"
}

variable "processor_schedule_expression" {
  description = "Finding reconciliation and handoff repair schedule."
  type        = string
  default     = "rate(15 minutes)"
}

variable "kubernetes_version" {
  description = "EKS minor compatible with the operator's Kubernetes 1.36 client libraries."
  type        = string
  default     = "1.36"

  validation {
    condition     = contains(["1.35", "1.36"], var.kubernetes_version)
    error_message = "kubernetes_version must be 1.35 or 1.36 for supported client-version skew."
  }
}

variable "eks_namespace" {
  description = "Namespace for generator access and operator/scanner resources."
  type        = string
  default     = "portscanner"
}

variable "eks_api_client_security_group_ids" {
  description = "Private runner or VPN security groups allowed to reach the private EKS API for Helm operations."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for security_group_id in var.eks_api_client_security_group_ids :
      can(regex("^sg-[0-9a-f]+$", security_group_id))
    ])
    error_message = "eks_api_client_security_group_ids must contain valid security group IDs."
  }
}

variable "eks_endpoint_public_access" {
  description = "Opt in to a restricted public EKS API endpoint for an evaluation runner. Private endpoint access remains enabled."
  type        = bool
  default     = false
}

variable "eks_public_access_cidrs" {
  description = "Restricted canonical IPv4 CIDRs allowed to reach the opt-in public EKS API endpoint. 0.0.0.0/0 is forbidden."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.eks_public_access_cidrs :
      cidr != "0.0.0.0/0" &&
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "eks_public_access_cidrs must contain restricted canonical IPv4 prefixes; 0.0.0.0/0 is forbidden."
  }
}

variable "eks_installer_principal_arns" {
  description = "Explicit IAM role or user ARNs granted EKS ClusterAdmin access for the Terraform Helm install."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.eks_installer_principal_arns :
      can(regex("^arn:[^:]+:iam::[0-9]{12}:(?:role|user)/.+$", arn))
    ])
    error_message = "eks_installer_principal_arns must contain IAM role or user ARNs, never STS session ARNs."
  }
}

variable "node_instance_types" {
  description = "Managed node types."
  type        = list(string)
  default     = ["t4g.medium"]
}

variable "node_ami_type" {
  description = "EKS-managed AMI type; no AMI ID is accepted."
  type        = string
  default     = "AL2023_ARM_64_STANDARD"

  validation {
    condition = contains(
      ["AL2023_ARM_64_STANDARD", "AL2023_x86_64_STANDARD"],
      var.node_ami_type
    )
    error_message = "node_ami_type must be an AL2023 ARM64 or x86_64 standard EKS AMI."
  }
}

variable "node_capacity_type" {
  description = "SPOT development default; production can use ON_DEMAND."
  type        = string
  default     = "SPOT"
}

variable "node_desired_size" {
  description = "Desired private node count."
  type        = number
  default     = 1
}

variable "node_min_size" {
  description = "Minimum private node count."
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum private node count."
  type        = number
  default     = 2
}

variable "node_disk_size_gib" {
  description = "Encrypted gp3 node root disk size."
  type        = number
  default     = 40
}

variable "bootstrap_cluster_creator_admin_permissions" {
  description = "Retain EKS bootstrap creator administration in addition to explicit installer access."
  type        = bool
  default     = false
}
