mock_provider "aws" {}

variables {
  name_prefix           = "test-functions"
  deploy_runtime        = true
  run_migration         = true
  enable_event_dispatch = false
  image_digests = {
    inventory = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    generator = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    parser    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    processor = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    migrator  = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    operator  = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    scanner   = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
  }
  repository_urls = {
    inventory = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/inventory"
    generator = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/generator"
    parser    = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/parser"
    processor = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/processor"
    migrator  = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/migrator"
  }
  function_role_arns = {
    snapshot         = "arn:aws:iam::123456789012:role/test-snapshot"
    signals          = "arn:aws:iam::123456789012:role/test-signals"
    outbox           = "arn:aws:iam::123456789012:role/test-outbox"
    rescan           = "arn:aws:iam::123456789012:role/test-rescan"
    generator        = "arn:aws:iam::123456789012:role/test-generator"
    target_projector = "arn:aws:iam::123456789012:role/test-target-projector"
    parser           = "arn:aws:iam::123456789012:role/test-parser"
    processor        = "arn:aws:iam::123456789012:role/test-processor"
    migrator         = "arn:aws:iam::123456789012:role/test-migrator"
  }
  private_subnet_ids         = ["subnet-00000000000000001", "subnet-00000000000000002"]
  security_group_id          = "sg-00000000000000001"
  database_security_group_id = "sg-00000000000000002"
  queue_urls = {
    priority       = "https://sqs.us-east-1.amazonaws.com/123456789012/test-priority"
    coverage       = "https://sqs.us-east-1.amazonaws.com/123456789012/test-coverage"
    "target-event" = "https://sqs.us-east-1.amazonaws.com/123456789012/test-target-event"
  }
  queue_arns = {
    signal         = "arn:aws:sqs:us-east-1:123456789012:test-signal"
    priority       = "arn:aws:sqs:us-east-1:123456789012:test-priority"
    coverage       = "arn:aws:sqs:us-east-1:123456789012:test-coverage"
    "target-event" = "arn:aws:sqs:us-east-1:123456789012:test-target-event"
    result         = "arn:aws:sqs:us-east-1:123456789012:test-result"
  }
  table_names = {
    inventory = "test-inventory"
    dispatch  = "test-dispatch"
  }
  table_stream_arns = {
    inventory = "arn:aws:dynamodb:us-east-1:123456789012:table/test-inventory/stream/2026-08-07T00:00:00.000"
  }
  bucket_names = {
    events   = "test-events"
    findings = "test-findings"
    results  = "test-results"
  }
  database_name                   = "portscanner"
  database_master_secret_arn      = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-master"
  database_application_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-application"
  database_application_username   = "portscanner_app"
  snapshot_backend                = "ec2"
  snapshot_account_id             = "123456789012"
  snapshot_regions                = ["us-east-1"]
  allowed_tag_keys                = ["application"]
  allowed_target_cidrs            = ["203.0.113.10/32"]
  denied_target_cidrs             = ["198.51.100.0/24"]
  authorized_account_ids          = ["123456789012"]
  eks_cluster_name                = "test-eks"
  eks_namespace                   = "portscanner"
  migration_checksum              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

run "migration_invocation_carries_expected_checksum" {
  command = plan

  assert {
    condition = (
      jsondecode(one(values(aws_lambda_invocation.migration)).input).direction == "up" &&
      jsondecode(one(values(aws_lambda_invocation.migration)).input).migration_checksum ==
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    error_message = "The migration invocation must carry the exact checksum used as its trigger."
  }

  assert {
    condition = (
      alltrue([
        for mapping in values(aws_lambda_event_source_mapping.sqs) :
        length(mapping.filter_criteria) == 0
      ]) &&
      jsondecode(
        one(one(aws_lambda_event_source_mapping.outbox[0].filter_criteria).filter).pattern
      ).eventName == ["INSERT"]
    )
    error_message = "Only the DynamoDB outbox mapping may carry the outbox stream filter."
  }
}

run "canary_enables_pipeline_without_automatic_inventory" {
  command = plan

  variables {
    enable_event_dispatch      = true
    enable_automatic_inventory = false
    canary_mode                = true
  }

  assert {
    condition = (
      alltrue([
        for name, mapping in aws_lambda_event_source_mapping.sqs :
        mapping.enabled == !contains(["signals", "generator_coverage"], name)
      ]) &&
      aws_lambda_event_source_mapping.outbox[0].enabled &&
      alltrue([
        for name, rule in aws_cloudwatch_event_rule.schedule :
        rule.state == (name == "outbox-replay" ? "ENABLED" : "DISABLED")
      ])
    )
    error_message = "Canary dispatch must enable durable outbox replay while keeping automatic inventory schedules disabled."
  }

  assert {
    condition = (
      aws_lambda_function.this["snapshot"].environment[0].variables["CANARY_MODE"] == "true" &&
      aws_lambda_function.this["snapshot"].environment[0].variables["AUTHORIZED_ACCOUNT_IDS"] == "123456789012" &&
      aws_lambda_function.this["snapshot"].environment[0].variables["AWS_REGIONS"] == "us-east-1" &&
      aws_lambda_function.this["generator_priority"].environment[0].variables["ALLOWED_TARGET_CIDRS"] == "203.0.113.10/32" &&
      aws_lambda_function.this["generator_priority"].environment[0].variables["DENIED_TARGET_CIDRS"] == "198.51.100.0/24"
    )
    error_message = "Snapshot and generator runtimes must receive fail-closed account, Region, and CIDR scope."
  }
}

run "paused_canary_retains_runtime_guard_with_dispatch_disabled" {
  command = plan

  variables {
    enable_event_dispatch      = false
    enable_automatic_inventory = false
    canary_mode                = true
  }

  assert {
    condition = (
      aws_lambda_function.this["snapshot"].environment[0].variables["CANARY_MODE"] == "true" &&
      alltrue([
        for mapping in aws_lambda_event_source_mapping.sqs :
        mapping.enabled == false
      ]) &&
      aws_lambda_event_source_mapping.outbox[0].enabled == false
    )
    error_message = "Paused canary mode must retain its runtime guard while every dispatch mapping is disabled."
  }
}

run "automatic_inventory_requires_dispatch_pipeline" {
  command = plan

  variables {
    enable_event_dispatch      = false
    enable_automatic_inventory = true
  }

  expect_failures = [terraform_data.runtime_validation]
}

run "activation_enables_recurring_schedules" {
  command = plan

  variables {
    enable_event_dispatch      = true
    enable_automatic_inventory = true
  }

  assert {
    condition = (
      alltrue([
        for rule in aws_cloudwatch_event_rule.schedule :
        rule.state == "ENABLED"
      ]) &&
      alltrue([
        for mapping in aws_lambda_event_source_mapping.sqs :
        mapping.enabled
      ])
    )
    error_message = "Full activation must enable every recurring schedule."
  }
}
