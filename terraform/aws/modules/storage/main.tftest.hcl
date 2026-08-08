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

run "reject_visibility_below_lambda_multiplier" {
  command = plan

  variables {
    lambda_timeout_seconds           = 60
    queue_visibility_timeout_seconds = 359
  }

  expect_failures = [terraform_data.storage_validation]
}
