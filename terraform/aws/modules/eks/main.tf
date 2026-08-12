terraform {
  required_version = "= 1.7.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.15.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "= 3.0.2"
    }
  }
}

variable "name_prefix" {
  description = "EKS cluster name."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets used by the control plane ENIs and managed nodes."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "EKS requires private subnets in at least two availability zones."
  }
}

variable "kubernetes_version" {
  description = "EKS minor compatible with the operator's Kubernetes 1.36 client libraries."
  type        = string
  default     = "1.36"

  validation {
    condition     = contains(["1.35", "1.36"], var.kubernetes_version)
    error_message = "kubernetes_version must be 1.35 or 1.36 for supported client-version skew."
  }
}

variable "control_plane_log_retention_days" {
  description = "Retention for EKS control-plane log groups managed by AWS."
  type        = number
  default     = 30
}

variable "node_instance_types" {
  description = "Managed node instance types. Defaults are low-volume ARM; external scanner/operator images must match."
  type        = list(string)
  default     = ["t4g.medium"]
}

variable "node_ami_type" {
  description = "EKS managed node AMI type. No AMI ID is hardcoded."
  type        = string
  default     = "AL2023_ARM_64_STANDARD"
}

variable "node_capacity_type" {
  description = "SPOT is the low-volume default; production can override to ON_DEMAND."
  type        = string
  default     = "SPOT"

  validation {
    condition     = contains(["SPOT", "ON_DEMAND"], var.node_capacity_type)
    error_message = "node_capacity_type must be SPOT or ON_DEMAND."
  }
}

variable "node_desired_size" {
  description = "Desired managed node count."
  type        = number
  default     = 1
}

variable "node_min_size" {
  description = "Minimum managed node count."
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum managed node count."
  type        = number
  default     = 2
}

variable "node_disk_size_gib" {
  description = "Encrypted gp3 root volume size."
  type        = number
  default     = 40
}

variable "bootstrap_cluster_creator_admin_permissions" {
  description = "Retain EKS bootstrap creator administration in addition to explicit installer entries. Disabled by default."
  type        = bool
  default     = false
}

variable "generator_role_arn" {
  description = "Generator Lambda role mapped to the chart-owned Kubernetes access group."
  type        = string
}

variable "generator_security_group_id" {
  description = "Private Lambda security group allowed to reach the EKS API over TLS."
  type        = string
}

variable "additional_api_client_security_group_ids" {
  description = "Additional private runner or VPN security groups allowed to reach the EKS API."
  type        = set(string)
  default     = []
}

variable "endpoint_public_access" {
  description = "Opt in to the EKS public API endpoint for a restricted evaluation runner. Private access remains enabled."
  type        = bool
  default     = false
}

variable "public_access_cidrs" {
  description = "Canonical IPv4 CIDRs allowed to reach an explicitly enabled public EKS API endpoint. An unrestricted CIDR is rejected."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.public_access_cidrs :
      cidr != "0.0.0.0/0" &&
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "public_access_cidrs must contain restricted canonical IPv4 prefixes; 0.0.0.0/0 is forbidden."
  }
}

variable "existing_interface_endpoint_security_group_ids" {
  description = "Validated existing interface endpoint security groups that receive TCP/443 ingress from the EKS cluster security group."
  type        = set(string)
  default     = []
}

variable "installer_principal_arns" {
  description = "IAM role or user ARNs granted explicit cluster-wide administration for Terraform Helm installation."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.installer_principal_arns :
      can(regex("^arn:[^:]+:iam::[0-9]{12}:(?:role|user)/.+$", arn))
    ])
    error_message = "installer_principal_arns must contain only IAM role or user ARNs, never STS session ARNs."
  }
}

variable "generator_access_group" {
  description = "Kubernetes group bound by the real operator chart to Scanner-only generator permissions."
  type        = string
  default     = "portscanner:generator"
}

variable "scanner_pod_role_arn" {
  description = "Pod Identity role restricted to the results object prefix."
  type        = string
}

variable "allowed_target_cidrs" {
  description = "Optional deployment-wide scanner allowlist of canonical IPv4 CIDRs."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.allowed_target_cidrs :
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "allowed_target_cidrs must contain only canonical IPv4 network prefixes."
  }
}

variable "denied_target_cidrs" {
  description = "Optional deployment-wide scanner denylist of canonical IPv4 CIDRs, enforced before the allowlist."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.denied_target_cidrs :
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", cidr)) &&
      can(cidrnetmask(cidr)) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "denied_target_cidrs must contain only canonical IPv4 network prefixes."
  }
}

variable "operator_max_concurrent_reconciles" {
  description = "Maximum concurrent Scanner reconciliations."
  type        = number
  default     = 4

  validation {
    condition     = var.operator_max_concurrent_reconciles >= 1 && var.operator_max_concurrent_reconciles <= 32 && floor(var.operator_max_concurrent_reconciles) == var.operator_max_concurrent_reconciles
    error_message = "operator_max_concurrent_reconciles must be an integer between 1 and 32."
  }
}

variable "scanner_max_concurrent_pods" {
  description = "Hard ResourceQuota limit for concurrently active scanner Pods."
  type        = number
  default     = 4

  validation {
    condition     = var.scanner_max_concurrent_pods >= 1 && var.scanner_max_concurrent_pods <= 100 && floor(var.scanner_max_concurrent_pods) == var.scanner_max_concurrent_pods
    error_message = "scanner_max_concurrent_pods must be an integer between 1 and 100."
  }
}

variable "scanner_max_jobs" {
  description = "Hard ResourceQuota limit for active, pending, and retained scanner Jobs."
  type        = number
  default     = 16

  validation {
    condition     = var.scanner_max_jobs >= 1 && var.scanner_max_jobs <= 1000 && floor(var.scanner_max_jobs) == var.scanner_max_jobs
    error_message = "scanner_max_jobs must be an integer between 1 and 1000."
  }
}

variable "scanner_min_rate" {
  description = "Minimum Nmap probe rate passed to every scanner Job."
  type        = number
  default     = 100

  validation {
    condition     = var.scanner_min_rate >= 1 && var.scanner_min_rate <= 2000 && floor(var.scanner_min_rate) == var.scanner_min_rate
    error_message = "scanner_min_rate must be an integer between 1 and 2000."
  }
}

variable "scanner_max_rate" {
  description = "Maximum Nmap probe rate passed to every scanner Job."
  type        = number
  default     = 500

  validation {
    condition     = var.scanner_max_rate >= 1 && var.scanner_max_rate <= 5000 && floor(var.scanner_max_rate) == var.scanner_max_rate
    error_message = "scanner_max_rate must be an integer between 1 and 5000."
  }
}

variable "chart_path" {
  description = "Absolute path to the repository's real portscanner Helm chart."
  type        = string
}

variable "namespace" {
  description = "Dedicated operator/scanner namespace."
  type        = string
  default     = "portscanner"
}

variable "install_operator" {
  description = "Install the namespace-scoped operator only after migration."
  type        = bool
  default     = false
}

variable "repository_urls" {
  description = "ECR URLs keyed by operator and scanner."
  type        = map(string)
}

variable "image_digests" {
  description = "Externally built image digests."
  type        = map(string)
  default     = {}
}

variable "migration_token" {
  description = "Dependency token emitted only after aws_lambda_invocation completes."
  type        = string
  default     = ""
}

variable "workload_architecture" {
  description = "Architecture used to build operator and scanner images."
  type        = string

  validation {
    condition     = contains(["arm64", "x86_64"], var.workload_architecture)
    error_message = "workload_architecture must be arm64 or x86_64."
  }
}

variable "results_bucket_name" {
  description = "Bucket to which scanner pods write result objects."
  type        = string
}

data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_ec2_instance_type" "node" {
  for_each = toset(var.node_instance_types)

  instance_type = each.value
}

locals {
  api_client_security_group_ids = setunion(
    toset([var.generator_security_group_id]),
    var.additional_api_client_security_group_ids
  )
}

resource "terraform_data" "node_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition = (
        var.node_min_size >= 0 &&
        var.node_desired_size >= var.node_min_size &&
        var.node_max_size >= var.node_desired_size
      )
      error_message = "Node scaling must satisfy 0 <= min <= desired <= max."
    }

    precondition {
      condition = (
        var.workload_architecture == "arm64" &&
        var.node_ami_type == "AL2023_ARM_64_STANDARD"
        ) || (
        var.workload_architecture == "x86_64" &&
        var.node_ami_type == "AL2023_x86_64_STANDARD"
      )
      error_message = "The EKS node AMI architecture must match the operator/scanner image architecture."
    }

    precondition {
      condition     = !contains(var.installer_principal_arns, var.generator_role_arn)
      error_message = "The generator role cannot also be an installer principal because EKS permits only one access entry per principal."
    }

    precondition {
      condition = (
        var.endpoint_public_access && length(var.public_access_cidrs) > 0
        ) || (
        !var.endpoint_public_access && length(var.public_access_cidrs) == 0
      )
      error_message = "Public EKS API access requires at least one restricted CIDR, and public_access_cidrs must be empty when public access is disabled."
    }

    precondition {
      condition = alltrue([
        for instance_type in values(data.aws_ec2_instance_type.node) :
        contains(instance_type.supported_architectures, var.workload_architecture)
      ])
      error_message = "Every node instance type must support the selected operator/scanner image architecture."
    }
  }
}

resource "terraform_data" "operator_validation" {
  input = {
    name            = var.name_prefix
    migration_token = var.migration_token
  }

  lifecycle {
    precondition {
      condition = !var.install_operator || (
        can(regex("^sha256:[0-9a-f]{64}$", var.image_digests["operator"])) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.image_digests["scanner"])) &&
        length(var.migration_token) > 0 &&
        length(var.installer_principal_arns) > 0
      )
      error_message = "install_operator requires operator/scanner digests, a completed migration token, and at least one explicit installer principal."
    }

    precondition {
      condition     = var.scanner_min_rate <= var.scanner_max_rate
      error_message = "scanner_min_rate must not exceed scanner_max_rate."
    }

    precondition {
      condition     = var.scanner_max_jobs >= var.scanner_max_concurrent_pods
      error_message = "scanner_max_jobs must be at least scanner_max_concurrent_pods."
    }

    precondition {
      condition = (
        abspath(var.chart_path) == var.chart_path &&
        fileexists("${var.chart_path}/Chart.yaml")
      )
      error_message = "chart_path must be an absolute path to the real portscanner chart."
    }
  }
}

resource "aws_kms_key" "eks" {
  description             = "EKS secret envelope encryption for ${var.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.name_prefix}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/aws/eks/${var.name_prefix}/cluster"
  retention_in_days = var.control_plane_log_retention_days
}

data "aws_iam_policy_document" "cluster_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name_prefix        = "${substr(var.name_prefix, 0, 36)}-cluster-"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = var.name_prefix
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = var.bootstrap_cluster_creator_admin_permissions
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access
    public_access_cidrs     = var.endpoint_public_access ? sort(tolist(var.public_access_cidrs)) : []
  }

  depends_on = [
    aws_cloudwatch_log_group.control_plane,
    aws_iam_role_policy_attachment.cluster
  ]
}

resource "aws_vpc_security_group_ingress_rule" "api_client" {
  for_each = local.api_client_security_group_ids

  security_group_id            = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = each.value
  description                  = "Private client access to the Kubernetes API"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "existing_endpoint_eks_workloads" {
  for_each = var.existing_interface_endpoint_security_group_ids

  security_group_id            = each.value
  referenced_security_group_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  description                  = "TLS from portscanner EKS workloads"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name_prefix        = "${substr(var.name_prefix, 0, 39)}-node-"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
}

locals {
  node_policy_arns = toset([
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
  ])
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = local.node_policy_arns

  role       = aws_iam_role.node.name
  policy_arn = each.value
}

resource "aws_launch_template" "node" {
  name_prefix            = "${var.name_prefix}-node-"
  update_default_version = true

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = var.node_disk_size_gib
      volume_type           = "gp3"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.name_prefix}-scanner-node"
    }
  }
}

resource "aws_eks_node_group" "scanner" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name_prefix}-scanner"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  ami_type       = var.node_ami_type
  capacity_type  = var.node_capacity_type
  instance_types = var.node_instance_types

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    workload = "scanner"
  }

  depends_on = [
    aws_iam_role_policy_attachment.node,
    aws_vpc_security_group_ingress_rule.existing_endpoint_eks_workloads
  ]
}

resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"

  depends_on = [aws_eks_node_group.scanner]
}

resource "aws_eks_pod_identity_association" "scanner" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = var.namespace
  service_account = "scanner"
  role_arn        = var.scanner_pod_role_arn

  depends_on = [aws_eks_addon.pod_identity]
}

resource "aws_eks_access_entry" "generator" {
  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = var.generator_role_arn
  type              = "STANDARD"
  user_name         = "${var.name_prefix}-generator"
  kubernetes_groups = [var.generator_access_group]
}

resource "aws_eks_access_entry" "installer" {
  for_each = var.installer_principal_arns

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "installer_cluster_admin" {
  for_each = var.installer_principal_arns

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.installer]
}

provider "helm" {
  kubernetes = {
    host                   = aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.this.certificate_authority[0].data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        aws_eks_cluster.this.name,
        "--region",
        data.aws_region.current.region
      ]
    }
  }
}

resource "helm_release" "operator" {
  count = var.install_operator ? 1 : 0

  name             = "portscanner"
  namespace        = var.namespace
  create_namespace = true
  chart            = var.chart_path
  atomic           = true
  cleanup_on_fail  = true
  wait             = true
  timeout          = 600

  values = [
    yamlencode({
      operator = {
        maxConcurrentReconciles = var.operator_max_concurrent_reconciles
        image = {
          repository = var.repository_urls["operator"]
          digest     = var.image_digests["operator"]
        }
        serviceAccount = {
          name = "operator"
        }
        nodeSelector = {
          workload = "scanner"
        }
      }
      scanner = {
        maxConcurrentPods = var.scanner_max_concurrent_pods
        maxJobs           = var.scanner_max_jobs
        image = {
          repository = var.repository_urls["scanner"]
          digest     = var.image_digests["scanner"]
        }
        serviceAccount = {
          name = "scanner"
        }
        authorization = {
          allowedCidrs = sort(tolist(var.allowed_target_cidrs))
          deniedCidrs  = sort(tolist(var.denied_target_cidrs))
        }
        tuning = {
          minRate = var.scanner_min_rate
          maxRate = var.scanner_max_rate
        }
        result = {
          bucket = var.results_bucket_name
          prefix = "results/"
        }
        nodeSelector = {
          workload = "scanner"
        }
      }
      generator = {
        rbac = {
          group = var.generator_access_group
        }
      }
    })
  ]

  depends_on = [
    terraform_data.operator_validation,
    aws_eks_access_entry.generator,
    aws_eks_access_policy_association.installer_cluster_admin,
    aws_eks_node_group.scanner,
    aws_eks_pod_identity_association.scanner,
    aws_vpc_security_group_ingress_rule.api_client
  ]
}

output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_arn" {
  value = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  value = aws_eks_cluster.this.certificate_authority[0].data
}

output "namespace" {
  value = var.namespace
}

output "operator_release_status" {
  value = try(helm_release.operator[0].status, "not-installed")
}
