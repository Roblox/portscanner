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
  description = "Prefix for Aurora and Secrets Manager resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC that contains the isolated database subnets."
  type        = string
}

variable "isolated_subnet_ids" {
  description = "At least two isolated subnets in distinct availability zones."
  type        = list(string)

  validation {
    condition     = length(var.isolated_subnet_ids) >= 2
    error_message = "Aurora requires at least two isolated subnets."
  }
}

variable "application_security_group_id" {
  description = "Security group for target projector, parser, processor, and migrator Aurora clients."
  type        = string
}

variable "additional_client_security_group_ids" {
  description = "Additional security groups allowed to connect to PostgreSQL. CIDR ingress is intentionally unsupported."
  type        = set(string)
  default     = []
}

variable "database_name" {
  description = "Initial application database."
  type        = string
  default     = "portscanner"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.database_name))
    error_message = "database_name must be a valid PostgreSQL identifier."
  }
}

variable "master_username" {
  description = "Aurora master username. Its password is managed by RDS in Secrets Manager."
  type        = string
  default     = "clusteradmin"
}

variable "engine_version" {
  description = "Supported Aurora PostgreSQL engine version for the selected region."
  type        = string
  default     = "16.4"
}

variable "instance_class" {
  description = "Aurora instance class. Increase and add instances for production."
  type        = string
  default     = "db.t4g.medium"
}

variable "instance_count" {
  description = "Aurora instances. One is a low-volume development default; production should use at least two."
  type        = number
  default     = 1

  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 15
    error_message = "instance_count must be between 1 and 15."
  }
}

variable "backup_retention_days" {
  description = "Automated backup retention. Production should use a value aligned with recovery requirements."
  type        = number
  default     = 7

  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "backup_retention_days must be between 1 and 35."
  }
}

variable "preferred_backup_window" {
  description = "Optional UTC backup window."
  type        = string
  default     = null
}

variable "deletion_protection" {
  description = "Protect the cluster from deletion. Production should set this true."
  type        = bool
  default     = false
}

variable "skip_final_snapshot" {
  description = "Skip a final snapshot on destroy. Production should set this false."
  type        = bool
  default     = true
}

variable "final_snapshot_identifier" {
  description = "Unique final snapshot identifier required when skip_final_snapshot is false."
  type        = string
  default     = null

  validation {
    condition     = var.final_snapshot_identifier == null || try(length(var.final_snapshot_identifier) > 0, false)
    error_message = "final_snapshot_identifier must be null or a non-empty string."
  }
}

variable "apply_immediately" {
  description = "Apply database modifications immediately instead of during the maintenance window."
  type        = bool
  default     = false
}

resource "terraform_data" "database_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition     = var.skip_final_snapshot || var.final_snapshot_identifier != null
      error_message = "final_snapshot_identifier is required when skip_final_snapshot is false."
    }
  }
}

resource "aws_security_group" "database" {
  name_prefix            = "${var.name_prefix}-database-"
  description            = "Aurora PostgreSQL; ingress is security-group referenced only"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = {
    Name = "${var.name_prefix}-database"
  }
}

locals {
  database_client_security_group_ids = setunion(
    toset([var.application_security_group_id]),
    var.additional_client_security_group_ids
  )
}

resource "aws_vpc_security_group_ingress_rule" "database" {
  for_each = local.database_client_security_group_ids

  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = each.value
  description                  = "PostgreSQL from an explicitly authorized application security group"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "application_database" {
  security_group_id            = var.application_security_group_id
  referenced_security_group_id = aws_security_group.database.id
  description                  = "PostgreSQL to Aurora"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_db_subnet_group" "this" {
  name_prefix = "${var.name_prefix}-"
  description = "Isolated Aurora subnets"
  subnet_ids  = var.isolated_subnet_ids

  tags = {
    Name = "${var.name_prefix}-database"
  }
}

resource "aws_secretsmanager_secret" "application" {
  name_prefix             = "${var.name_prefix}/database/application-"
  description             = "Application PostgreSQL credential populated and rotated by the migrator"
  recovery_window_in_days = 7

  tags = {
    CredentialOwner = "migrator"
  }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier_prefix   = "${var.name_prefix}-"
  engine                      = "aurora-postgresql"
  engine_mode                 = "provisioned"
  engine_version              = var.engine_version
  database_name               = var.database_name
  master_username             = var.master_username
  manage_master_user_password = true

  db_subnet_group_name                = aws_db_subnet_group.this.name
  vpc_security_group_ids              = [aws_security_group.database.id]
  port                                = 5432
  storage_encrypted                   = true
  iam_database_authentication_enabled = true

  backup_retention_period = var.backup_retention_days
  preferred_backup_window = var.preferred_backup_window
  copy_tags_to_snapshot   = true

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : var.final_snapshot_identifier
  apply_immediately         = var.apply_immediately

  tags = {
    Name = var.name_prefix
  }
}

resource "aws_rds_cluster_instance" "this" {
  count = var.instance_count

  identifier_prefix  = "${var.name_prefix}-${count.index + 1}-"
  cluster_identifier = aws_rds_cluster.this.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.this.engine
  engine_version     = aws_rds_cluster.this.engine_version

  db_subnet_group_name         = aws_db_subnet_group.this.name
  publicly_accessible          = false
  auto_minor_version_upgrade   = true
  apply_immediately            = var.apply_immediately
  performance_insights_enabled = false

  tags = {
    Name = "${var.name_prefix}-${count.index + 1}"
  }
}

output "cluster_arn" {
  value = aws_rds_cluster.this.arn
}

output "cluster_endpoint" {
  value = aws_rds_cluster.this.endpoint
}

output "cluster_reader_endpoint" {
  value = aws_rds_cluster.this.reader_endpoint
}

output "cluster_port" {
  value = aws_rds_cluster.this.port
}

output "database_name" {
  value = aws_rds_cluster.this.database_name
}

output "database_security_group_id" {
  value = aws_security_group.database.id
}

output "application_security_group_id" {
  value = var.application_security_group_id
}

output "master_secret_arn" {
  value     = try(aws_rds_cluster.this.master_user_secret[0].secret_arn, null)
  sensitive = true
}

output "application_secret_arn" {
  value = aws_secretsmanager_secret.application.arn
}
