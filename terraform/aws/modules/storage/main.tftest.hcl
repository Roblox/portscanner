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
  name_prefix = "test-storage"
  cloudtrail_source_arns = [
    "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-management"
  ]
}

run "queue_visibility_defaults_to_six_times_lambda_timeout" {
  command = plan

  assert {
    condition = alltrue([
      for queue in values(aws_sqs_queue.main) :
      queue.visibility_timeout_seconds == 360
    ])
    error_message = "Every primary queue must use the safe 360-second default."
  }
}

run "inventory_table_indexes_durable_pending_outbox" {
  command = plan

  assert {
    condition = (
      one(aws_dynamodb_table.inventory.global_secondary_index).name == "entity-event-index" &&
      one(aws_dynamodb_table.inventory.global_secondary_index).hash_key == "entity" &&
      one(aws_dynamodb_table.inventory.global_secondary_index).range_key == "event_id"
    )
    error_message = "The inventory table must expose the durable pending-outbox replay index."
  }
}

run "reject_visibility_below_lambda_multiplier" {
  command = plan

  variables {
    lambda_timeout_seconds           = 60
    queue_visibility_timeout_seconds = 359
  }

  expect_failures = [terraform_data.storage_validation]
}

run "database_boundary_omits_finding_integration" {
  command = plan

  variables {
    finding_export_enabled = false
  }

  assert {
    condition = (
      !contains(keys(aws_s3_bucket.data), "findings") &&
      !contains(keys(aws_sqs_queue.main), "finding") &&
      !contains(keys(aws_sqs_queue.dead_letter), "finding") &&
      !contains(keys(aws_cloudwatch_metric_alarm.queue_age), "finding") &&
      !contains(keys(aws_cloudwatch_metric_alarm.dead_letter_messages), "finding") &&
      length(aws_s3_bucket_notification.findings) == 0
    )
    error_message = "Database-only mode must omit all finding export storage, notifications, and alarms."
  }

  assert {
    condition = (
      output.finding_bucket_name == null &&
      output.finding_bucket_arn == null &&
      output.finding_queue_url == null &&
      output.finding_queue_arn == null
    )
    error_message = "Disabled finding export outputs must be safely nullable."
  }
}

run "disabled_cloudtrail_storage_is_nullable" {
  command = plan

  variables {
    enable_cloudtrail_storage = false
    cloudtrail_source_arns    = []
  }

  assert {
    condition = (
      !contains(keys(aws_s3_bucket.data), "cloudtrail") &&
      output.cloudtrail_bucket_name == null
    )
    error_message = "Disabled CloudTrail mode must not retain an unused CloudTrail bucket."
  }
}
