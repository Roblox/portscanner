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

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name_prefix = "test-identities"
  bucket_arns = {
    events  = "arn:aws:s3:::test-events"
    results = "arn:aws:s3:::test-results"
  }
  queue_arns = {
    signal         = "arn:aws:sqs:us-east-1:123456789012:test-signal"
    priority       = "arn:aws:sqs:us-east-1:123456789012:test-priority"
    coverage       = "arn:aws:sqs:us-east-1:123456789012:test-coverage"
    "target-event" = "arn:aws:sqs:us-east-1:123456789012:test-target-event"
    result         = "arn:aws:sqs:us-east-1:123456789012:test-result"
  }
  table_arns = {
    inventory = "arn:aws:dynamodb:us-east-1:123456789012:table/test-inventory"
    dispatch  = "arn:aws:dynamodb:us-east-1:123456789012:table/test-dispatch"
  }
  table_stream_arns = {
    inventory = "arn:aws:dynamodb:us-east-1:123456789012:table/test-inventory/stream/test"
  }
  database_master_secret_arn      = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-master"
  database_application_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-application"
  eks_cluster_arn                 = "arn:aws:eks:us-east-1:123456789012:cluster/test"
  finding_export_enabled          = false
}

run "database_boundary_omits_finding_object_permissions" {
  command = plan

  assert {
    condition = (
      !strcontains(aws_iam_role_policy.function["target_projector"].policy, "PublishFindingObjects") &&
      !strcontains(aws_iam_role_policy.function["parser"].policy, "PublishFindingObjects") &&
      !strcontains(aws_iam_role_policy.function["processor"].policy, "PublishFindingObjects") &&
      !strcontains(aws_iam_role_policy.function["parser"].policy, "test-findings")
    )
    error_message = "Database-only runtimes must not require finding bucket permissions."
  }

  assert {
    condition = (
      strcontains(aws_iam_role_policy.function["target_projector"].policy, "test-events") &&
      strcontains(aws_iam_role_policy.function["parser"].policy, "test-results") &&
      strcontains(aws_iam_role_policy.function["processor"].policy, "ReadApplicationDatabaseCredential")
    )
    error_message = "Core database and input-object permissions must remain present."
  }
}
