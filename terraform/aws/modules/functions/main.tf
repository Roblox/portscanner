terraform {
  required_version = "= 1.7.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.15.0"
    }
  }
}

variable "name_prefix" {
  description = "Prefix for Lambda functions and schedules."
  type        = string
}

variable "deploy_runtime" {
  description = "Create digest-pinned runtime functions. Event sources remain disabled until enable_event_dispatch."
  type        = bool
  default     = false
}

variable "run_migration" {
  description = "Invoke the digest-pinned migrator for migration_checksum."
  type        = bool
  default     = false
}

variable "enable_event_dispatch" {
  description = "Enable queue, stream, and schedule event sources."
  type        = bool
  default     = false
}

variable "image_digests" {
  description = "Externally built image digests keyed by inventory, generator, parser, processor, migrator, operator, and scanner."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, digest in var.image_digests :
      contains(["inventory", "generator", "parser", "processor", "migrator", "operator", "scanner"], name) &&
      can(regex("^sha256:[0-9a-f]{64}$", digest))
    ])
    error_message = "image_digests may contain only supported image names and each value must be a sha256 digest."
  }
}

variable "repository_urls" {
  description = "ECR repository URLs keyed by image name."
  type        = map(string)
}

variable "function_role_arns" {
  description = "Execution roles keyed by snapshot, signals, outbox, rescan, generator, target_projector, parser, processor, and migrator."
  type        = map(string)
}

variable "private_subnet_ids" {
  description = "Private Lambda subnets."
  type        = list(string)
}

variable "security_group_id" {
  description = "Private runtime security group without database access."
  type        = string
}

variable "database_security_group_id" {
  description = "Private security group used by every PostgreSQL client function."
  type        = string
}

variable "queue_urls" {
  description = "Queue URLs keyed by purpose."
  type        = map(string)
}

variable "queue_arns" {
  description = "Queue ARNs keyed by purpose."
  type        = map(string)
}

variable "table_names" {
  description = "DynamoDB table names keyed by purpose."
  type        = map(string)
}

variable "table_stream_arns" {
  description = "DynamoDB table stream ARNs keyed by purpose."
  type        = map(string)
}

variable "bucket_names" {
  description = "Bucket names keyed by purpose."
  type        = map(string)
}

variable "database_name" {
  description = "Application database name."
  type        = string
}

variable "database_master_secret_arn" {
  description = "RDS-managed master credential secret."
  type        = string
  sensitive   = true
}

variable "database_application_secret_arn" {
  description = "Migrator-populated application credential secret."
  type        = string
}

variable "config_aggregator_name" {
  description = "AWS Config aggregator queried by snapshot, or null when Config snapshots are disabled."
  type        = string
  default     = null
}

variable "snapshot_backend" {
  description = "Inventory snapshot backend: config or ec2."
  type        = string

  validation {
    condition     = contains(["config", "ec2"], var.snapshot_backend)
    error_message = "snapshot_backend must be config or ec2."
  }
}

variable "snapshot_account_id" {
  description = "Default account for direct EC2 snapshots."
  type        = string
}

variable "snapshot_regions" {
  description = "Regions collected by the direct EC2 snapshot backend."
  type        = list(string)
}

variable "allowed_tag_keys" {
  description = "Shared AWS context tag keys allowed into target contracts."
  type        = set(string)
  default     = []
}

variable "target_event_prefix" {
  description = "Immutable target-event object prefix."
  type        = string
  default     = "target-events/aws"
}

variable "authorized_account_ids" {
  description = "Explicit inventory and dispatch scope."
  type        = set(string)
  default     = []
}

variable "member_collector_role_arns" {
  description = "Exact EC2 Describe-only member collector roles keyed by account ID."
  type        = map(string)
  default     = {}
}

variable "member_collector_external_ids" {
  description = "External IDs paired with member collector roles by account ID."
  type        = map(string)
  default     = {}
}

variable "eks_cluster_name" {
  description = "EKS cluster used by generator functions."
  type        = string
}

variable "eks_namespace" {
  description = "Namespace to which generator access is scoped."
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "Timeout for queue-triggered functions."
  type        = number
  default     = 60
}

variable "migration_timeout_seconds" {
  description = "Timeout for the one-shot database migrator."
  type        = number
  default     = 900
}

variable "memory_size_mb" {
  description = "Memory for ordinary runtime functions."
  type        = number
  default     = 512
}

variable "migration_memory_size_mb" {
  description = "Memory for the migrator."
  type        = number
  default     = 1024
}

variable "architecture" {
  description = "Lambda image architecture; external images must match."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 or x86_64."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention."
  type        = number
  default     = 14
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
  description = "Existing action ARNs invoked when a Lambda alarm enters ALARM; empty creates alarms without actions."
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
  description = "Existing action ARNs invoked when a Lambda alarm returns to OK."
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

variable "reserved_concurrency" {
  description = "Reserved concurrency by function. Tune these conservative defaults for production throughput."
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

variable "migration_checksum" {
  description = "Checksum of ordered migration content; changing it creates a new aws_lambda_invocation."
  type        = string
  default     = ""
}

variable "database_application_username" {
  description = "Least-privilege database username created by the migrator."
  type        = string
}

variable "processor_schedule_expression" {
  description = "Finding reconciliation and handoff repair schedule."
  type        = string
  default     = "rate(15 minutes)"
}

locals {
  required_images = toset([
    "inventory",
    "generator",
    "parser",
    "processor",
    "migrator",
    "operator",
    "scanner"
  ])

  member_collector_role_templates = toset([
    for account_id, role_arn in var.member_collector_role_arns :
    replace(role_arn, "::${account_id}:role/", "::{account_id}:role/")
  ])
  member_collector_external_id_values = toset(values(var.member_collector_external_ids))
  member_discovery_environment = length(var.member_collector_role_arns) == 0 ? tomap({}) : tomap({
    DISCOVERY_ROLE_ARN_TEMPLATE = one(local.member_collector_role_templates)
    DISCOVERY_EXTERNAL_ID       = one(local.member_collector_external_id_values)
  })

  inventory_environment = merge({
    INVENTORY_TABLE     = var.table_names["inventory"]
    TARGET_EVENT_BUCKET = var.bucket_names["events"]
    TARGET_EVENT_PREFIX = var.target_event_prefix
    SNAPSHOT_BACKEND    = var.snapshot_backend
    AWS_ACCOUNT_ID      = var.snapshot_account_id
    ALLOWED_TAG_KEYS    = join(",", sort(tolist(var.allowed_tag_keys)))
  }, local.member_discovery_environment)

  snapshot_environment = merge(
    local.inventory_environment,
    var.snapshot_backend == "config" ? {
      CONFIG_AGGREGATOR_NAME = var.config_aggregator_name
      } : {
      AWS_ACCOUNT_ID = var.snapshot_account_id
      AWS_REGIONS    = join(",", var.snapshot_regions)
    }
  )

  generator_environment = merge(local.inventory_environment, {
    TARGET_EVENT_BUCKET = var.bucket_names["events"]
    TARGET_EVENT_PREFIX = var.target_event_prefix
    IDEMPOTENCY_TABLE   = var.table_names["dispatch"]
    INVENTORY_TABLE     = var.table_names["inventory"]
    EKS_CLUSTER_NAME    = var.eks_cluster_name
    K8S_NAMESPACE       = var.eks_namespace
    K8S_API_GROUP       = "scanning.portscanner.io"
    K8S_API_VERSION     = "v1alpha1"
    K8S_CRD_PLURAL      = "scanners"
  })

  function_definitions = {
    snapshot = {
      image       = "inventory"
      role        = "snapshot"
      command     = "portscanner_inventory.handlers.snapshot.lambda_handler"
      timeout     = var.lambda_timeout_seconds
      memory      = var.memory_size_mb
      environment = local.snapshot_environment
    }
    signals = {
      image       = "inventory"
      role        = "signals"
      command     = "portscanner_inventory.handlers.signals.lambda_handler"
      timeout     = var.lambda_timeout_seconds
      memory      = var.memory_size_mb
      environment = local.inventory_environment
    }
    outbox = {
      image   = "inventory"
      role    = "outbox"
      command = "portscanner_inventory.handlers.outbox.lambda_handler"
      timeout = var.lambda_timeout_seconds
      memory  = var.memory_size_mb
      environment = merge(local.inventory_environment, {
        PRIORITY_QUEUE_URL     = var.queue_urls["priority"]
        COVERAGE_QUEUE_URL     = var.queue_urls["coverage"]
        TARGET_EVENT_QUEUE_URL = var.queue_urls["target-event"]
      })
    }
    rescan = {
      image       = "inventory"
      role        = "rescan"
      command     = "portscanner_inventory.handlers.rescan.lambda_handler"
      timeout     = var.lambda_timeout_seconds
      memory      = var.memory_size_mb
      environment = local.inventory_environment
    }
    generator_priority = {
      image       = "generator"
      role        = "generator"
      command     = "portscanner_generator.handler.lambda_handler"
      timeout     = var.lambda_timeout_seconds
      memory      = var.memory_size_mb
      environment = local.generator_environment
    }
    generator_coverage = {
      image       = "generator"
      role        = "generator"
      command     = "portscanner_generator.handler.lambda_handler"
      timeout     = var.lambda_timeout_seconds
      memory      = var.memory_size_mb
      environment = local.generator_environment
    }
    target_projector = {
      image   = "parser"
      role    = "target_projector"
      command = "act_parser.target_handler.lambda_handler"
      timeout = var.lambda_timeout_seconds
      memory  = var.memory_size_mb
      environment = {
        TARGET_EVENT_BUCKET = var.bucket_names["events"]
        TARGET_EVENT_PREFIX = var.target_event_prefix
        FINDING_BUCKET      = var.bucket_names["findings"]
        DB_SECRET_ID        = var.database_application_secret_arn
      }
    }
    parser = {
      image   = "parser"
      role    = "parser"
      command = "act_parser.handler.lambda_handler"
      timeout = var.lambda_timeout_seconds
      memory  = var.memory_size_mb
      environment = {
        SCAN_RESULT_BUCKET = var.bucket_names["results"]
        RAW_RESULT_BUCKET  = var.bucket_names["results"]
        FINDING_BUCKET     = var.bucket_names["findings"]
        DB_SECRET_ID       = var.database_application_secret_arn
      }
    }
    processor = {
      image   = "processor"
      role    = "processor"
      command = "act_processor.handler.lambda_handler"
      timeout = var.lambda_timeout_seconds
      memory  = var.memory_size_mb
      environment = {
        FINDING_BUCKET = var.bucket_names["findings"]
        DB_SECRET_ID   = var.database_application_secret_arn
      }
    }
    migrator = {
      image   = "migrator"
      role    = "migrator"
      command = "act_migrator.handler.lambda_handler"
      timeout = var.migration_timeout_seconds
      memory  = var.migration_memory_size_mb
      environment = {
        DB_SECRET_ID             = var.database_master_secret_arn
        DB_NAME                  = var.database_name
        DB_APPLICATION_SECRET_ID = var.database_application_secret_arn
        DB_APPLICATION_USERNAME  = var.database_application_username
      }
    }
  }

  active_functions = var.deploy_runtime ? local.function_definitions : {}

  sqs_mappings = {
    signals = {
      function = "signals"
      queue    = "signal"
    }
    generator_priority = {
      function = "generator_priority"
      queue    = "priority"
    }
    generator_coverage = {
      function = "generator_coverage"
      queue    = "coverage"
    }
    target_projector = {
      function = "target_projector"
      queue    = "target-event"
    }
    parser = {
      function = "parser"
      queue    = "result"
    }
  }

  snapshot_scope_account_ids = length(var.authorized_account_ids) > 0 ? var.authorized_account_ids : toset([
    var.snapshot_account_id
  ])
  snapshot_schedules = {
    for account_id in local.snapshot_scope_account_ids :
    "snapshot-${account_id}" => {
      expression = var.snapshot_schedule_expression
      function   = "snapshot"
      input = {
        account_id = account_id
      }
    }
  }
  schedules = merge(local.snapshot_schedules, {
    rescan = {
      expression = var.rescan_schedule_expression
      function   = "rescan"
      input      = null
    }
    processor = {
      expression = var.processor_schedule_expression
      function   = "processor"
      input      = null
    }
  })

  migration_key = var.deploy_runtime && var.run_migration ? sha256(
    "${var.image_digests["migrator"]}:${var.migration_checksum}"
  ) : null
}

resource "terraform_data" "runtime_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition = !var.deploy_runtime || alltrue([
        for image in local.required_images :
        can(regex("^sha256:[0-9a-f]{64}$", var.image_digests[image]))
      ])
      error_message = "deploy_runtime requires an externally built sha256 digest for every supported image."
    }

    precondition {
      condition     = !var.run_migration || (var.deploy_runtime && can(regex("^[0-9a-f]{64}$", var.migration_checksum)))
      error_message = "run_migration requires deploy_runtime and a 64-character lowercase migration_checksum."
    }

    precondition {
      condition     = !var.enable_event_dispatch || (var.deploy_runtime && var.run_migration && length(var.authorized_account_ids) > 0)
      error_message = "enable_event_dispatch requires deployed runtime, completed migration, and an explicit authorized account scope."
    }

    precondition {
      condition     = toset(keys(var.member_collector_role_arns)) == toset(keys(var.member_collector_external_ids))
      error_message = "Member collector role and external-ID maps must have identical account keys."
    }

    precondition {
      condition = length(var.member_collector_role_arns) == 0 || (
        length(local.member_collector_role_templates) == 1 &&
        length(local.member_collector_external_id_values) == 1
      )
      error_message = "Direct member collection requires one shared collector role path/name and external ID across account scopes."
    }

    precondition {
      condition = length(setsubtract(
        var.authorized_account_ids,
        toset([var.snapshot_account_id])
        )) == 0 || (
        toset(keys(var.member_collector_role_arns)) == var.authorized_account_ids
      )
      error_message = "Every authorized scope requires an exact collector role when any non-local account is collected."
    }

    precondition {
      condition     = var.snapshot_backend != "config" || try(length(var.config_aggregator_name) > 0, false)
      error_message = "Config snapshots require config_aggregator_name."
    }

    precondition {
      condition = var.snapshot_backend != "ec2" || (
        can(regex("^[0-9]{12}$", var.snapshot_account_id)) &&
        length(var.snapshot_regions) > 0 &&
        alltrue([
          for region in var.snapshot_regions :
          can(regex("^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", region))
        ])
      )
      error_message = "EC2 snapshots require a 12-digit snapshot_account_id and at least one valid snapshot region."
    }

    precondition {
      condition = length(setsubtract(
        var.allowed_tag_keys,
        toset(["application", "environment", "name", "service"])
      )) == 0
      error_message = "allowed_tag_keys contains a key outside the shared AWS contract."
    }

    precondition {
      condition = alltrue([
        for function_name in keys(local.function_definitions) :
        lookup(var.reserved_concurrency, function_name, -2) >= -1
      ])
      error_message = "reserved_concurrency must define every function with a value of -1 or greater."
    }
  }
}

resource "aws_cloudwatch_log_group" "function" {
  for_each = local.active_functions

  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "this" {
  for_each = local.active_functions

  function_name = "${var.name_prefix}-${each.key}"
  description   = "Digest-pinned ${each.key} runtime"
  package_type  = "Image"
  image_uri     = "${var.repository_urls[each.value.image]}@${var.image_digests[each.value.image]}"
  role          = var.function_role_arns[each.value.role]

  architectures                  = [var.architecture]
  timeout                        = each.value.timeout
  memory_size                    = each.value.memory
  reserved_concurrent_executions = var.reserved_concurrency[each.key]

  image_config {
    command = [each.value.command]
  }

  environment {
    variables = each.value.environment
  }

  vpc_config {
    subnet_ids = var.private_subnet_ids
    security_group_ids = contains(
      ["target_projector", "parser", "processor", "migrator"],
      each.key
      ) ? [
      var.database_security_group_id
    ] : [var.security_group_id]
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.function[each.key].name
  }

  depends_on = [aws_cloudwatch_log_group.function]
}

resource "aws_cloudwatch_metric_alarm" "function_errors" {
  for_each = aws_lambda_function.this

  alarm_name          = "${each.value.function_name}-errors"
  alarm_description   = "The ${each.key} Lambda reported at least one invocation error."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns

  dimensions = {
    FunctionName = each.value.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "function_throttles" {
  for_each = aws_lambda_function.this

  alarm_name          = "${each.value.function_name}-throttles"
  alarm_description   = "The ${each.key} Lambda reported at least one throttled invocation."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns

  dimensions = {
    FunctionName = each.value.function_name
  }
}

resource "aws_lambda_invocation" "migration" {
  for_each = local.migration_key == null ? {} : {
    (local.migration_key) = local.migration_key
  }

  function_name = aws_lambda_function.this["migrator"].function_name
  input = jsonencode({
    direction          = "up"
    migration_checksum = var.migration_checksum
  })

  triggers = {
    image_digest       = var.image_digests["migrator"]
    migration_checksum = var.migration_checksum
  }

  lifecycle {
    postcondition {
      condition = try(
        jsondecode(self.result).direction == "up" &&
        jsondecode(self.result).migration_checksum == var.migration_checksum,
        false
      )
      error_message = "Migrator response did not verify the exact requested migration_checksum."
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs" {
  for_each = var.deploy_runtime ? local.sqs_mappings : {}

  event_source_arn = var.queue_arns[each.value.queue]
  function_name    = aws_lambda_function.this[each.value.function].arn
  enabled          = var.enable_event_dispatch
  batch_size       = 5

  function_response_types = ["ReportBatchItemFailures"]

  depends_on = [aws_lambda_invocation.migration]
}

resource "aws_lambda_event_source_mapping" "outbox" {
  count = var.deploy_runtime ? 1 : 0

  event_source_arn  = var.table_stream_arns["inventory"]
  function_name     = aws_lambda_function.this["outbox"].arn
  enabled           = var.enable_event_dispatch
  starting_position = "TRIM_HORIZON"
  batch_size        = 10

  function_response_types = ["ReportBatchItemFailures"]

  depends_on = [aws_lambda_invocation.migration]
}

resource "aws_cloudwatch_metric_alarm" "outbox_iterator_age" {
  count = var.deploy_runtime ? 1 : 0

  alarm_name          = "${aws_lambda_function.this["outbox"].function_name}-iterator-age"
  alarm_description   = "The inventory outbox DynamoDB stream iterator age has exceeded ${var.iterator_age_alarm_threshold_seconds} seconds."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "IteratorAge"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Maximum"
  threshold           = var.iterator_age_alarm_threshold_seconds * 1000
  treat_missing_data  = "notBreaching"
  unit                = "Milliseconds"

  alarm_actions = var.alarm_action_arns
  ok_actions    = var.ok_action_arns

  dimensions = {
    FunctionName = aws_lambda_function.this["outbox"].function_name
  }

  depends_on = [aws_lambda_event_source_mapping.outbox]
}

resource "aws_cloudwatch_event_rule" "schedule" {
  for_each = {
    for name, schedule in local.schedules :
    name => schedule if var.deploy_runtime
  }

  name                = "${var.name_prefix}-${each.key}-schedule"
  description         = "Conservative ${each.key} schedule"
  schedule_expression = each.value.expression
  state               = var.enable_event_dispatch ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "schedule" {
  for_each = aws_cloudwatch_event_rule.schedule

  rule = each.value.name
  arn  = aws_lambda_function.this[local.schedules[each.key].function].arn
  input = local.schedules[each.key].input == null ? null : jsonencode(
    local.schedules[each.key].input
  )

  depends_on = [aws_lambda_invocation.migration]
}

resource "aws_lambda_permission" "schedule" {
  for_each = aws_cloudwatch_event_rule.schedule

  statement_id  = "AllowEventBridge${title(each.key)}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this[local.schedules[each.key].function].function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}

output "function_arns" {
  value = { for name, function in aws_lambda_function.this : name => function.arn }
}

output "migration_token" {
  description = "Becomes known only after the keyed migration invocation completes."
  value = try(
    "${values(aws_lambda_invocation.migration)[0].id}:${keys(aws_lambda_invocation.migration)[0]}",
    ""
  )
}

output "alarm_names" {
  description = "CloudWatch Lambda alarm names keyed by alarm class and function."
  value = {
    errors = {
      for name, alarm in aws_cloudwatch_metric_alarm.function_errors :
      name => alarm.alarm_name
    }
    throttles = {
      for name, alarm in aws_cloudwatch_metric_alarm.function_throttles :
      name => alarm.alarm_name
    }
    outbox_iterator_age = try(aws_cloudwatch_metric_alarm.outbox_iterator_age[0].alarm_name, null)
  }
}

output "alarm_arns" {
  description = "CloudWatch Lambda alarm ARNs keyed by alarm class and function."
  value = {
    errors = {
      for name, alarm in aws_cloudwatch_metric_alarm.function_errors :
      name => alarm.arn
    }
    throttles = {
      for name, alarm in aws_cloudwatch_metric_alarm.function_throttles :
      name => alarm.arn
    }
    outbox_iterator_age = try(aws_cloudwatch_metric_alarm.outbox_iterator_age[0].arn, null)
  }
}
