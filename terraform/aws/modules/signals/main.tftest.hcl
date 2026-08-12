mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
}

variables {
  name_prefix                  = "test-signals"
  signal_queue_arn             = "arn:aws:sqs:us-east-1:123456789012:test-signal"
  signal_dead_letter_queue_arn = "arn:aws:sqs:us-east-1:123456789012:test-signal-dlq"
  config_mode                  = "create"
  config_delivery_bucket_name  = "test-config-delivery"
  cloudtrail_name              = "test-management"
  cloudtrail_bucket_name       = "test-cloudtrail"
  create_central_event_bus     = false
  authorized_account_ids       = ["123456789012"]
  config_aggregator_account_ids = [
    "123456789012"
  ]
}

run "created_config_is_explicitly_regional" {
  command = plan

  assert {
    condition     = aws_config_configuration_aggregator.this[0].account_aggregation_source[0].all_regions == false
    error_message = "A single recorder must not claim all-region Config coverage."
  }

  assert {
    condition = toset(
      aws_config_configuration_aggregator.this[0].account_aggregation_source[0].regions
    ) == toset(["us-east-1"])
    error_message = "The created aggregator must include only the explicitly recorded region."
  }

  assert {
    condition = (
      aws_config_aggregate_authorization.self[0].account_id == "123456789012" &&
      aws_config_aggregate_authorization.self[0].authorized_aws_region == "us-east-1"
    )
    error_message = "Create mode must authorize its exact account and aggregator region."
  }
}

run "disabled_cloudtrail_keeps_only_native_local_state_hint" {
  command = plan

  variables {
    config_mode     = "disabled"
    cloudtrail_mode = "disabled"
  }

  assert {
    condition = (
      length(aws_cloudtrail.management) == 0 &&
      !contains(keys(aws_cloudwatch_event_rule.local), "cloudtrail") &&
      contains(keys(aws_cloudwatch_event_rule.local), "state")
    )
    error_message = "Disabled CloudTrail mode must omit the trail and local API-call rule while retaining native state hints."
  }
}

run "existing_cloudtrail_mode_requires_exact_arn" {
  command = plan

  variables {
    cloudtrail_mode = "existing"
  }

  expect_failures = [terraform_data.signal_validation]
}
