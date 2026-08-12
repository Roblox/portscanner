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
  description = "Prefix for execution role names."
  type        = string
}

variable "bucket_arns" {
  description = "Bucket ARNs keyed by events, results, findings, and cloudtrail."
  type        = map(string)
}

variable "queue_arns" {
  description = "Queue ARNs keyed by queue purpose."
  type        = map(string)
}

variable "table_arns" {
  description = "DynamoDB table ARNs keyed by inventory and dispatch."
  type        = map(string)
}

variable "table_stream_arns" {
  description = "DynamoDB stream ARNs keyed by table purpose."
  type        = map(string)
}

variable "database_master_secret_arn" {
  description = "RDS-managed master credential secret ARN."
  type        = string
  sensitive   = true
}

variable "database_application_secret_arn" {
  description = "Application credential secret ARN."
  type        = string
}

variable "eks_cluster_arn" {
  description = "Deterministic EKS cluster ARN used by generator permissions."
  type        = string
}

variable "member_collector_role_arns" {
  description = "Exact member-account collector roles the snapshot function may assume."
  type        = list(string)
  default     = []
}

variable "result_object_prefix" {
  description = "Only this results bucket prefix is writable by scanner pods."
  type        = string
  default     = "results/"
}

variable "target_event_object_prefix" {
  description = "Immutable target-event object prefix."
  type        = string
  default     = "target-events/aws/"
}

variable "finding_object_prefix" {
  description = "Immutable finding handoff object prefix."
  type        = string
  default     = "findings/"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  function_roles = toset([
    "snapshot",
    "signals",
    "outbox",
    "rescan",
    "generator",
    "target_projector",
    "parser",
    "processor",
    "migrator"
  ])

  common_statements = [
    {
      Sid    = "WriteFunctionLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = [
        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name_prefix}-*:*"
      ]
    },
    {
      Sid    = "ManageVpcNetworkInterfaces"
      Effect = "Allow"
      Action = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DeleteNetworkInterface",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses"
      ]
      Resource = ["*"]
    }
  ]

  function_statements = {
    snapshot = concat([
      {
        Sid      = "ReadConfigInventory"
        Effect   = "Allow"
        Action   = ["config:SelectAggregateResourceConfig"]
        Resource = ["*"]
      },
      {
        Sid      = "DescribeEc2Inventory"
        Effect   = "Allow"
        Action   = ["ec2:Describe*"]
        Resource = ["*"]
      },
      {
        Sid    = "ReconcileInventory"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:TransactWriteItems"
        ]
        Resource = [var.table_arns["inventory"]]
      }
      ], length(var.member_collector_role_arns) == 0 ? [] : [
      {
        Sid      = "AssumeExactMemberCollectors"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.member_collector_role_arns
      }
    ])
    signals = concat([
      {
        Sid    = "ConsumeSignals"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage"
        ]
        Resource = [var.queue_arns["signal"]]
      },
      {
        Sid      = "ResolveSignalInventory"
        Effect   = "Allow"
        Action   = ["ec2:Describe*"]
        Resource = ["*"]
      },
      {
        Sid    = "ReconcileSignalState"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Scan",
          "dynamodb:TransactWriteItems"
        ]
        Resource = [var.table_arns["inventory"]]
      }
      ], length(var.member_collector_role_arns) == 0 ? [] : [
      {
        Sid      = "AssumeExactMemberCollectors"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.member_collector_role_arns
      }
    ])
    outbox = [
      {
        Sid    = "ConsumeInventoryOutboxStream"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator"
        ]
        Resource = [var.table_stream_arns["inventory"]]
      },
      {
        Sid      = "ListDynamoStreams"
        Effect   = "Allow"
        Action   = ["dynamodb:ListStreams"]
        Resource = ["*"]
      },
      {
        Sid    = "RepairInventoryOutbox"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [var.table_arns["inventory"]]
      },
      {
        Sid      = "ListPendingInventoryOutbox"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = ["${var.table_arns["inventory"]}/index/entity-event-index"]
      },
      {
        Sid    = "PublishTargetEventObject"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${var.bucket_arns["events"]}/${var.target_event_object_prefix}*"]
      },
      {
        Sid    = "RouteTargetEvent"
        Effect = "Allow"
        Action = ["sqs:SendMessage"]
        Resource = [
          var.queue_arns["priority"],
          var.queue_arns["coverage"],
          var.queue_arns["target-event"]
        ]
      }
    ]
    rescan = [
      {
        Sid    = "CreateCoverageOutboxEvents"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:TransactWriteItems"
        ]
        Resource = [var.table_arns["inventory"]]
      }
    ]
    generator = concat([
      {
        Sid    = "ConsumeGenerationRequests"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage"
        ]
        Resource = [
          var.queue_arns["priority"],
          var.queue_arns["coverage"]
        ]
      },
      {
        Sid    = "ReadTargetEventObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = ["${var.bucket_arns["events"]}/${var.target_event_object_prefix}*"]
      },
      {
        Sid      = "ReadInventoryState"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = [var.table_arns["inventory"]]
      },
      {
        Sid    = "RecordDispatchClaims"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [var.table_arns["dispatch"]]
      },
      {
        Sid    = "UseNamespaceScopedEksAccess"
        Effect = "Allow"
        Action = [
          "eks:AccessKubernetesApi",
          "eks:DescribeCluster"
        ]
        Resource = [var.eks_cluster_arn]
      }
      ], length(var.member_collector_role_arns) == 0 ? [] : [
      {
        Sid      = "AssumeExactMemberCollectors"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.member_collector_role_arns
      }
    ])
    target_projector = [
      {
        Sid    = "ConsumeTargetEvents"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage"
        ]
        Resource = [var.queue_arns["target-event"]]
      },
      {
        Sid    = "ReadTargetEventObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = ["${var.bucket_arns["events"]}/${var.target_event_object_prefix}*"]
      },
      {
        Sid    = "PublishFindingObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${var.bucket_arns["findings"]}/${var.finding_object_prefix}*"]
      },
      {
        Sid      = "ReadApplicationDatabaseCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.database_application_secret_arn]
      }
    ]
    parser = [
      {
        Sid    = "ConsumeScanResults"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage"
        ]
        Resource = [var.queue_arns["result"]]
      },
      {
        Sid    = "ReadResultObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = ["${var.bucket_arns["results"]}/${var.result_object_prefix}*"]
      },
      {
        Sid    = "PublishFindingObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${var.bucket_arns["findings"]}/${var.finding_object_prefix}*"]
      },
      {
        Sid      = "ReadApplicationDatabaseCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.database_application_secret_arn]
      }
    ]
    processor = [
      {
        Sid    = "PublishFindingObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${var.bucket_arns["findings"]}/${var.finding_object_prefix}*"]
      },
      {
        Sid      = "ReadApplicationDatabaseCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.database_application_secret_arn]
      }
    ]
    migrator = [
      {
        Sid    = "ReadMasterCredential"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ]
        Resource = [var.database_master_secret_arn]
      },
      {
        Sid    = "InitializeApplicationCredential"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = [var.database_application_secret_arn]
      }
    ]
  }
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "function" {
  for_each = local.function_roles

  name_prefix        = "${substr(var.name_prefix, 0, 24)}-${each.key}-"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json

  tags = {
    FunctionGroup = each.key
  }
}

resource "aws_iam_role_policy" "function" {
  for_each = aws_iam_role.function

  name = "least-privilege-runtime"
  role = each.value.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.common_statements, local.function_statements[each.key])
  })
}

data "aws_iam_policy_document" "pod_identity_assume" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole",
      "sts:TagSession"
    ]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner_pod" {
  name_prefix        = "${substr(var.name_prefix, 0, 30)}-scanner-"
  assume_role_policy = data.aws_iam_policy_document.pod_identity_assume.json

  tags = {
    Workload = "scanner"
  }
}

resource "aws_iam_role_policy" "scanner_pod" {
  name = "result-prefix-write-only"
  role = aws_iam_role.scanner_pod.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteResultPrefixOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${var.bucket_arns["results"]}/${var.result_object_prefix}*"]
      }
    ]
  })
}

output "function_role_arns" {
  value      = { for name, role in aws_iam_role.function : name => role.arn }
  depends_on = [aws_iam_role_policy.function]
}

output "snapshot_role_arn" {
  value      = aws_iam_role.function["snapshot"].arn
  depends_on = [aws_iam_role_policy.function]
}

output "signals_role_arn" {
  value      = aws_iam_role.function["signals"].arn
  depends_on = [aws_iam_role_policy.function]
}

output "generator_role_arn" {
  value      = aws_iam_role.function["generator"].arn
  depends_on = [aws_iam_role_policy.function]
}

output "scanner_pod_role_arn" {
  value      = aws_iam_role.scanner_pod.arn
  depends_on = [aws_iam_role_policy.scanner_pod]
}
