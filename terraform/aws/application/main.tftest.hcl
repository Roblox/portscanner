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

  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["arm64"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

mock_provider "helm" {}

run "database_boundary_has_nullable_integration_outputs" {
  command = plan

  variables {
    config_mode     = "disabled"
    cloudtrail_mode = "disabled"
  }

  assert {
    condition = (
      output.finding_queue_url == null &&
      output.finding_queue_arn == null &&
      output.finding_bucket_name == null &&
      output.finding_bucket_arn == null &&
      output.cloudtrail_arn == null &&
      output.managed_canary_public_ip == null &&
      output.managed_canary_status_function_arn == null &&
      !contains(keys(output.bucket_names), "findings") &&
      !contains(keys(output.bucket_names), "cloudtrail")
    )
    error_message = "The default PostgreSQL boundary must expose safe nulls for disabled integrations."
  }
}

run "managed_canary_composes_after_scanner_network" {
  command = plan

  variables {
    config_mode            = "disabled"
    cloudtrail_mode        = "disabled"
    managed_canary_enabled = true
  }

  assert {
    condition = (
      output.managed_canary.listener_port == 18080 &&
      output.managed_canary.inventory_tag_key == "service" &&
      output.managed_canary_snapshot_invocation.payload.operation == "managed-canary" &&
      output.managed_canary_status_invocation.payload.operation == "managed-canary-status"
    )
    error_message = "Application composition must expose only the trusted canary and status operations."
  }
}
