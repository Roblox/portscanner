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
  name_prefix = "test-repositories"
}

run "expiration_is_disabled_by_default" {
  command = plan

  assert {
    condition     = length(aws_ecr_lifecycle_policy.this) == 0
    error_message = "ECR lifecycle expiration must be opt-in."
  }

  assert {
    condition     = alltrue([for repository in values(aws_ecr_repository.this) : !repository.force_delete])
    error_message = "ECR force deletion must be opt-in."
  }
}

run "optional_expiration_never_selects_tagged_images" {
  command = plan

  variables {
    untagged_image_expiration_days = 30
  }

  assert {
    condition = alltrue([
      for policy in values(aws_ecr_lifecycle_policy.this) :
      jsondecode(policy.policy).rules[0].selection.tagStatus == "untagged"
    ])
    error_message = "Optional ECR expiration must select only untagged images."
  }
}

run "disposable_evaluation_can_delete_repositories" {
  command = plan

  variables {
    force_delete = true
  }

  assert {
    condition     = alltrue([for repository in values(aws_ecr_repository.this) : repository.force_delete])
    error_message = "The explicit disposable-evaluation setting must permit repository cleanup."
  }
}
