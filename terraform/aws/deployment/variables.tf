variable "environment" {
  description = "The sole user-maintained, non-secret deployment configuration."
  type = object({
    name = string
    aws = object({
      account_id = string
      region     = string
    })
    network = object({
      vpc_cidr           = string
      availability_zones = list(string)
      az_count           = number
      nat_gateway_mode   = string
    })
    runner = object({
      eks_installer_principal_arn = string
      restricted_public_cidr      = string
    })
    retention = object({
      disposable               = bool
      destroy_data_on_teardown = bool
      database_backup_days     = number
      lambda_log_days          = number
      ecr_untagged_image_days  = number
      bucket_expiration_days   = map(number)
    })
    scanner = object({
      operator_max_concurrent_reconciles = number
      max_concurrent_pods                = number
      max_jobs                           = number
      min_rate                           = number
      max_rate                           = number
      architecture                       = string
      node_instance_type                 = string
    })
    managed_canary = object({
      enabled                   = bool
      vpc_cidr                  = string
      instance_type             = string
      listen_port               = number
      expected_finding_severity = string
    })
    integrations = object({
      recurring_inventory_enabled     = bool
      signal_hints_enabled            = bool
      finding_export_enabled          = bool
      config_mode                     = string
      existing_config_aggregator_name = string
      snapshot_regions                = list(string)
      cloudtrail_mode                 = string
      existing_cloudtrail_arn         = string
      authorized_account_ids          = set(string)
      allowed_target_cidrs            = set(string)
      denied_target_cidrs             = set(string)
      allowed_eni_interface_types     = set(string)
      required_target_tag_key         = string
      required_target_tag_value       = string
    })
  })

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.environment.name))
    error_message = "environment.name must be 2-20 lowercase alphanumeric or hyphen characters."
  }

  validation {
    condition     = can(regex("^[0-9]{12}$", var.environment.aws.account_id))
    error_message = "environment.aws.account_id must be a 12-digit AWS account ID."
  }

  validation {
    condition     = can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", var.environment.aws.region))
    error_message = "environment.aws.region must be an AWS Region name."
  }

  validation {
    condition = (
      can(cidrnetmask(var.environment.network.vpc_cidr)) &&
      try(cidrhost(var.environment.network.vpc_cidr, 0) == split("/", var.environment.network.vpc_cidr)[0], false) &&
      try(tonumber(split("/", var.environment.network.vpc_cidr)[1]) >= 16, false) &&
      try(tonumber(split("/", var.environment.network.vpc_cidr)[1]) <= 24, false)
    )
    error_message = "environment.network.vpc_cidr must be a canonical IPv4 /16 through /24."
  }

  validation {
    condition = (
      var.environment.network.az_count >= 2 &&
      var.environment.network.az_count <= 3 &&
      floor(var.environment.network.az_count) == var.environment.network.az_count &&
      contains(["single", "one_per_az"], var.environment.network.nat_gateway_mode)
    )
    error_message = "environment.network must select 2-3 AZs and single or one_per_az NAT."
  }

  validation {
    condition = (
      can(regex(
        "^arn:[^:]+:iam::${var.environment.aws.account_id}:(?:role|user)/.+$",
        var.environment.runner.eks_installer_principal_arn
      )) &&
      var.environment.runner.restricted_public_cidr != "0.0.0.0/0" &&
      can(cidrnetmask(var.environment.runner.restricted_public_cidr)) &&
      try(cidrhost(var.environment.runner.restricted_public_cidr, 0) == split("/", var.environment.runner.restricted_public_cidr)[0], false) &&
      try(tonumber(split("/", var.environment.runner.restricted_public_cidr)[1]) == 32, false)
    )
    error_message = "environment.runner requires a same-account IAM role/user ARN and one canonical public IPv4 /32."
  }

  validation {
    condition = (
      !var.environment.retention.destroy_data_on_teardown ||
      var.environment.retention.disposable
    )
    error_message = "destroy_data_on_teardown may be true only for an explicitly disposable environment."
  }

  validation {
    condition = (
      var.environment.retention.database_backup_days >= 1 &&
      var.environment.retention.database_backup_days <= 35 &&
      var.environment.retention.lambda_log_days >= 1 &&
      var.environment.retention.ecr_untagged_image_days >= 1 &&
      toset(keys(var.environment.retention.bucket_expiration_days)) == toset([
        "cloudtrail",
        "events",
        "findings",
        "results"
      ]) &&
      alltrue([
        for days in values(var.environment.retention.bucket_expiration_days) :
        days >= 1 && floor(days) == days
      ])
    )
    error_message = "retention values must be positive, and bucket_expiration_days must define cloudtrail, events, findings, and results."
  }

  validation {
    condition = (
      var.environment.scanner.operator_max_concurrent_reconciles >= 1 &&
      var.environment.scanner.operator_max_concurrent_reconciles <= 32 &&
      floor(var.environment.scanner.operator_max_concurrent_reconciles) == var.environment.scanner.operator_max_concurrent_reconciles &&
      var.environment.scanner.max_concurrent_pods >= 1 &&
      var.environment.scanner.max_concurrent_pods <= 100 &&
      floor(var.environment.scanner.max_concurrent_pods) == var.environment.scanner.max_concurrent_pods &&
      var.environment.scanner.max_jobs >= 1 &&
      var.environment.scanner.max_jobs <= 1000 &&
      floor(var.environment.scanner.max_jobs) == var.environment.scanner.max_jobs &&
      var.environment.scanner.min_rate >= 1 &&
      var.environment.scanner.max_rate <= 5000 &&
      var.environment.scanner.min_rate <= var.environment.scanner.max_rate
    )
    error_message = "environment.scanner limits must be positive, integral, within application bounds, and min_rate must not exceed max_rate."
  }

  validation {
    condition = (
      (var.environment.scanner.architecture == "arm64" && startswith(var.environment.scanner.node_instance_type, "t4g.")) ||
      (var.environment.scanner.architecture == "x86_64" && startswith(var.environment.scanner.node_instance_type, "t3."))
    )
    error_message = "The low-cost canonical root supports arm64 with t4g.* or x86_64 with t3.* nodes."
  }

  validation {
    condition = (
      can(cidrnetmask(var.environment.managed_canary.vpc_cidr)) &&
      try(cidrhost(var.environment.managed_canary.vpc_cidr, 0) == split("/", var.environment.managed_canary.vpc_cidr)[0], false) &&
      try(tonumber(split("/", var.environment.managed_canary.vpc_cidr)[1]) == 28, false) &&
      startswith(var.environment.managed_canary.instance_type, "t4g.") &&
      var.environment.managed_canary.listen_port == 18080 &&
      var.environment.managed_canary.expected_finding_severity == "low"
    )
    error_message = "managed_canary requires a canonical /28, ARM t4g instance, fixed TCP 18080 listener, and low expected severity."
  }

  validation {
    condition = (
      contains(["create", "existing", "disabled"], var.environment.integrations.config_mode) &&
      contains(["create", "existing", "disabled"], var.environment.integrations.cloudtrail_mode) &&
      (
        var.environment.integrations.config_mode != "existing" ||
        length(var.environment.integrations.existing_config_aggregator_name) > 0
      ) &&
      (
        var.environment.integrations.cloudtrail_mode != "existing" ||
        length(var.environment.integrations.existing_cloudtrail_arn) > 0
      )
    )
    error_message = "integration modes must be create, existing, or disabled and existing modes require their referenced resource."
  }

  validation {
    condition = alltrue([
      for account_id in var.environment.integrations.authorized_account_ids :
      can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "integrations.authorized_account_ids must contain only 12-digit AWS account IDs."
  }

  validation {
    condition = alltrue([
      for region in var.environment.integrations.snapshot_regions :
      can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", region))
    ])
    error_message = "integrations.snapshot_regions must contain valid AWS Region names."
  }

  validation {
    condition = alltrue([
      for cidr in setunion(
        var.environment.integrations.allowed_target_cidrs,
        var.environment.integrations.denied_target_cidrs
      ) :
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "integration target CIDRs must be canonical IP network prefixes."
  }

  validation {
    condition = (
      length(var.environment.integrations.allowed_eni_interface_types) > 0 &&
      alltrue([
        for interface_type in var.environment.integrations.allowed_eni_interface_types :
        can(regex("^[a-z0-9-]+$", interface_type))
      ]) &&
      contains(
        ["application", "environment", "name", "service"],
        var.environment.integrations.required_target_tag_key
      ) &&
      length(var.environment.integrations.required_target_tag_value) > 0
    )
    error_message = "integrations requires supported ENI interface types and one non-empty allowed target tag."
  }
}

variable "deploy_runtime" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "run_migration" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "install_operator" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "enable_event_dispatch" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "enable_automatic_inventory" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "canary_mode" {
  description = "Internal staged-deployment gate; do not set in environment configuration."
  type        = bool
  default     = false
}

variable "image_digests" {
  description = "Generated immutable image digests; written by bootstrap.sh."
  type        = map(string)
  default     = {}
}

variable "migration_checksum" {
  description = "Generated migration checksum; written by bootstrap.sh."
  type        = string
  default     = ""
}

variable "lambda_architecture" {
  description = "Generated confirmation of the applied workload architecture."
  type        = string
  default     = null
  nullable    = true
}

variable "node_ami_type" {
  description = "Generated confirmation of the applied EKS AMI architecture."
  type        = string
  default     = null
  nullable    = true
}

variable "node_instance_types" {
  description = "Generated confirmation of the applied EKS instance types."
  type        = list(string)
  default     = null
  nullable    = true
}
