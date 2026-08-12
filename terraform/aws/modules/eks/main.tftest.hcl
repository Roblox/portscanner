mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["arm64"]
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

mock_provider "helm" {}

variables {
  name_prefix                 = "test-eks"
  private_subnet_ids          = ["subnet-00000000000000001", "subnet-00000000000000002"]
  generator_role_arn          = "arn:aws:iam::123456789012:role/test-generator"
  generator_security_group_id = "sg-00000000000000001"
  existing_interface_endpoint_security_group_ids = [
    "sg-00000000000000002"
  ]
  scanner_pod_role_arn = "arn:aws:iam::123456789012:role/test-scanner"
  chart_path           = abspath("../../../../operator/chart/portscanner")
  repository_urls = {
    operator = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/operator"
    scanner  = "123456789012.dkr.ecr.us-east-1.amazonaws.com/test/scanner"
  }
  image_digests = {
    operator = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    scanner  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
  migration_token       = "verified-migration"
  workload_architecture = "arm64"
  results_bucket_name   = "test-results"
}

run "reject_install_without_explicit_installer" {
  command = plan

  variables {
    install_operator = true
  }

  expect_failures = [terraform_data.operator_validation]
}

run "reject_public_endpoint_without_cidrs" {
  command = plan

  variables {
    endpoint_public_access = true
  }

  expect_failures = [terraform_data.node_validation]
}

run "reject_unrestricted_public_endpoint" {
  command = plan

  variables {
    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]
  }

  expect_failures = [var.public_access_cidrs]
}

run "create_restricted_public_endpoint" {
  command = plan

  variables {
    endpoint_public_access = true
    public_access_cidrs    = ["198.51.100.24/32"]
  }

  assert {
    condition = (
      aws_eks_cluster.this.vpc_config[0].endpoint_private_access &&
      aws_eks_cluster.this.vpc_config[0].endpoint_public_access &&
      toset(aws_eks_cluster.this.vpc_config[0].public_access_cidrs) == toset(["198.51.100.24/32"])
    )
    error_message = "Evaluation public access must retain private access and use only the configured restricted CIDRs."
  }
}

run "create_explicit_cluster_admin_path" {
  command = plan

  variables {
    install_operator = true
    installer_principal_arns = [
      "arn:aws:iam::123456789012:role/test-installer"
    ]
  }

  assert {
    condition     = aws_eks_cluster.this.access_config[0].bootstrap_cluster_creator_admin_permissions == false
    error_message = "Explicit installer access must not rely on bootstrap creator administration."
  }

  assert {
    condition = (
      aws_eks_access_entry.installer["arn:aws:iam::123456789012:role/test-installer"].principal_arn ==
      "arn:aws:iam::123456789012:role/test-installer"
    )
    error_message = "The installer must receive an explicit EKS access entry."
  }

  assert {
    condition = (
      aws_eks_access_policy_association.installer_cluster_admin["arn:aws:iam::123456789012:role/test-installer"].policy_arn ==
      "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    )
    error_message = "The installer access entry must receive cluster-wide administration."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.existing_endpoint_eks_workloads["sg-00000000000000002"].security_group_id ==
      "sg-00000000000000002" &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_eks_workloads["sg-00000000000000002"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_eks_workloads["sg-00000000000000002"].to_port == 443
    )
    error_message = "The selected interface endpoint security group must allow EKS workload TLS."
  }

  assert {
    condition = (
      strcontains(helm_release.operator[0].values[0], "maxConcurrentReconciles") &&
      strcontains(helm_release.operator[0].values[0], "maxConcurrentPods") &&
      strcontains(helm_release.operator[0].values[0], "maxJobs") &&
      strcontains(helm_release.operator[0].values[0], "minRate") &&
      strcontains(helm_release.operator[0].values[0], "maxRate")
    )
    error_message = "The Helm release must carry explicit scanner concurrency and rate policy."
  }
}

run "reject_job_quota_below_active_pod_quota" {
  command = plan

  variables {
    scanner_max_concurrent_pods = 5
    scanner_max_jobs            = 4
  }

  expect_failures = [terraform_data.operator_validation]
}

run "reject_inverted_scanner_rate_range" {
  command = plan

  variables {
    scanner_min_rate = 501
    scanner_max_rate = 500
  }

  expect_failures = [terraform_data.operator_validation]
}
