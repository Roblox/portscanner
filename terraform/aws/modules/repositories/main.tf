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
  description = "Prefix for ECR repository names."
  type        = string
}

variable "untagged_image_expiration_days" {
  description = "Optional age for expiring only untagged images. Null disables lifecycle expiration; tagged release images are never expired here."
  type        = number
  default     = null

  validation {
    condition     = var.untagged_image_expiration_days == null ? true : var.untagged_image_expiration_days >= 1
    error_message = "untagged_image_expiration_days must be null or positive."
  }
}

variable "force_delete" {
  description = "Delete repository images during Terraform destroy. Enable only for a disposable evaluation."
  type        = bool
  default     = false
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  image_names = toset([
    "inventory",
    "generator",
    "parser",
    "processor",
    "migrator",
    "operator",
    "scanner"
  ])
  lambda_image_names = toset([
    "inventory",
    "generator",
    "parser",
    "processor",
    "migrator"
  ])
}

resource "aws_ecr_repository" "this" {
  for_each = local.image_names

  name                 = "${var.name_prefix}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_delete

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Component = each.key
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each = var.untagged_image_expiration_days == null ? toset([]) : local.image_names

  repository = aws_ecr_repository.this[each.key].name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire only untagged images after the configured age"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_image_expiration_days
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_repository_policy" "lambda" {
  for_each = {
    for name, repository in aws_ecr_repository.this :
    name => repository if contains(local.lambda_image_names, name)
  }

  repository = each.value.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "LambdaDigestImageRetrieval"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ]
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        StringLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${var.name_prefix}-*"
        }
      }
    }]
  })
}

output "repository_urls" {
  value      = { for name, repository in aws_ecr_repository.this : name => repository.repository_url }
  depends_on = [aws_ecr_repository_policy.lambda]
}

output "repository_arns" {
  value = { for name, repository in aws_ecr_repository.this : name => repository.arn }
}

output "repository_names" {
  value = { for name, repository in aws_ecr_repository.this : name => repository.name }
}
