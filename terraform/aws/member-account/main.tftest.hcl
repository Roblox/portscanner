mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "222222222222"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-west-2"
    }
  }
}

variables {
  name_prefix             = "test-member"
  central_event_bus_arn   = "arn:aws:events:us-east-1:123456789012:event-bus/test-central"
  enable_event_forwarding = true
}

run "reject_api_event_forwarding_without_cloudtrail" {
  command = plan

  expect_failures = [terraform_data.member_validation]
}

run "reference_management_trail_for_regional_forwarding" {
  command = plan

  variables {
    cloudtrail_mode         = "existing"
    existing_cloudtrail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/organization-management"
  }

  assert {
    condition = alltrue([
      for rule in values(aws_cloudwatch_event_rule.ec2_hint) :
      rule.state == "ENABLED"
    ])
    error_message = "Member forwarding rules must be enabled only with an explicit trail path."
  }

  assert {
    condition     = output.signal_region == "us-west-2"
    error_message = "A member forwarding root must expose its one regional hot path."
  }
}
