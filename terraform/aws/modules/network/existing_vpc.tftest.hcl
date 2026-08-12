mock_provider "aws" {
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

override_data {
  target = data.aws_vpc.existing[0]
  values = {
    id                   = "vpc-00000000000000001"
    enable_dns_support   = true
    enable_dns_hostnames = true
  }
}

override_data {
  target = data.aws_subnet.existing_private["subnet-00000000000000001"]
  values = {
    vpc_id                  = "vpc-00000000000000001"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = false
  }
}

override_data {
  target = data.aws_subnet.existing_private["subnet-00000000000000002"]
  values = {
    vpc_id                  = "vpc-00000000000000001"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = false
  }
}

override_data {
  target = data.aws_subnet.existing_isolated["subnet-00000000000000003"]
  values = {
    vpc_id                  = "vpc-00000000000000001"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = false
  }
}

override_data {
  target = data.aws_subnet.existing_isolated["subnet-00000000000000004"]
  values = {
    vpc_id                  = "vpc-00000000000000001"
    availability_zone       = "us-east-1b"
    map_public_ip_on_launch = false
  }
}

override_data {
  target = data.aws_route_table.existing_private["subnet-00000000000000001"]
  values = {
    id     = "rtb-00000000000000001"
    routes = []
  }
}

override_data {
  target = data.aws_route_table.existing_private["subnet-00000000000000002"]
  values = {
    id     = "rtb-00000000000000002"
    routes = []
  }
}

override_data {
  target = data.aws_route_table.existing_isolated["subnet-00000000000000003"]
  values = {
    id     = "rtb-00000000000000003"
    routes = []
  }
}

override_data {
  target = data.aws_route_table.existing_isolated["subnet-00000000000000004"]
  values = {
    id     = "rtb-00000000000000004"
    routes = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["config"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.config"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["dynamodb"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.dynamodb"
    vpc_endpoint_type   = "Gateway"
    private_dns_enabled = false
    security_group_ids  = []
    route_table_ids     = ["rtb-00000000000000001", "rtb-00000000000000002"]
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["ec2"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.ec2"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["ecr.api"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.ecr.api"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["ecr.dkr"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.ecr.dkr"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["eks"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.eks"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["eks-auth"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.eks-auth"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["logs"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.logs"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["s3"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.s3"
    vpc_endpoint_type   = "Gateway"
    private_dns_enabled = false
    security_group_ids  = []
    route_table_ids     = ["rtb-00000000000000001", "rtb-00000000000000002"]
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["secretsmanager"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.secretsmanager"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["sqs"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.sqs"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

override_data {
  target = data.aws_vpc_endpoint.existing_private["sts"]
  values = {
    vpc_id              = "vpc-00000000000000001"
    state               = "available"
    service_name        = "com.amazonaws.us-east-1.sts"
    vpc_endpoint_type   = "Interface"
    private_dns_enabled = true
    security_group_ids  = ["sg-00000000000000001"]
    route_table_ids     = []
  }
}

variables {
  name_prefix                         = "test-existing"
  create_vpc                          = false
  existing_vpc_id                     = "vpc-00000000000000001"
  existing_private_subnet_egress_mode = "vpc_endpoints"
  existing_private_subnet_ids = [
    "subnet-00000000000000001",
    "subnet-00000000000000002"
  ]
  existing_isolated_subnet_ids = [
    "subnet-00000000000000003",
    "subnet-00000000000000004"
  ]
  existing_private_vpc_endpoint_ids = {
    config         = "vpce-00000000000000001"
    dynamodb       = "vpce-00000000000000002"
    ec2            = "vpce-00000000000000003"
    "ecr.api"      = "vpce-00000000000000004"
    "ecr.dkr"      = "vpce-00000000000000005"
    eks            = "vpce-00000000000000006"
    "eks-auth"     = "vpce-00000000000000007"
    logs           = "vpce-00000000000000008"
    s3             = "vpce-00000000000000009"
    secretsmanager = "vpce-0000000000000000a"
    sqs            = "vpce-0000000000000000b"
    sts            = "vpce-0000000000000000c"
  }
  existing_private_interface_endpoint_security_group_ids = {
    config         = "sg-00000000000000001"
    ec2            = "sg-00000000000000001"
    "ecr.api"      = "sg-00000000000000001"
    "ecr.dkr"      = "sg-00000000000000001"
    eks            = "sg-00000000000000001"
    "eks-auth"     = "sg-00000000000000001"
    logs           = "sg-00000000000000001"
    secretsmanager = "sg-00000000000000001"
    sqs            = "sg-00000000000000001"
    sts            = "sg-00000000000000001"
  }
}

run "reject_missing_private_egress_declaration" {
  command = plan

  variables {
    existing_private_subnet_egress_mode                    = null
    existing_private_vpc_endpoint_ids                      = {}
    existing_private_interface_endpoint_security_group_ids = {}
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_existing_vpc_without_dns_support" {
  command = plan

  override_data {
    target = data.aws_vpc.existing[0]
    values = {
      id                   = "vpc-00000000000000001"
      enable_dns_support   = false
      enable_dns_hostnames = true
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_existing_vpc_without_dns_hostnames" {
  command = plan

  override_data {
    target = data.aws_vpc.existing[0]
    values = {
      id                   = "vpc-00000000000000001"
      enable_dns_support   = true
      enable_dns_hostnames = false
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "accept_explicit_complete_endpoint_egress" {
  command = plan

  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_runtime) == 1 &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_runtime["sg-00000000000000001"].security_group_id ==
      "sg-00000000000000001" &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_runtime["sg-00000000000000001"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_runtime["sg-00000000000000001"].to_port == 443
    )
    error_message = "The selected interface endpoint security group must allow runtime Lambda TLS."
  }

  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_database) == 1 &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_database["sg-00000000000000001"].security_group_id ==
      "sg-00000000000000001" &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_database["sg-00000000000000001"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.existing_endpoint_lambda_database["sg-00000000000000001"].to_port == 443
    )
    error_message = "The selected interface endpoint security group must allow database Lambda TLS."
  }
}

run "reject_endpoint_only_subnets_when_scanner_dispatch_is_enabled" {
  command = plan

  variables {
    scanner_public_egress_required = true
  }

  expect_failures = [terraform_data.network_validation]
}

run "accept_verified_public_nat_scanner_egress" {
  command = plan

  variables {
    existing_private_subnet_egress_mode                    = "nat_gateway"
    existing_private_vpc_endpoint_ids                      = {}
    existing_private_interface_endpoint_security_group_ids = {}
    existing_public_nat_gateway_ids                        = ["nat-00000000000000001"]
    scanner_public_egress_required                         = true
  }

  override_data {
    target = data.aws_route_table.existing_private["subnet-00000000000000001"]
    values = {
      id = "rtb-00000000000000001"
      routes = [{
        cidr_block     = "0.0.0.0/0"
        nat_gateway_id = "nat-00000000000000001"
        state          = "active"
      }]
    }
  }

  override_data {
    target = data.aws_route_table.existing_private["subnet-00000000000000002"]
    values = {
      id = "rtb-00000000000000002"
      routes = [{
        cidr_block     = "0.0.0.0/0"
        nat_gateway_id = "nat-00000000000000001"
        state          = "active"
      }]
    }
  }

  override_data {
    target = data.aws_nat_gateway.existing_public["nat-00000000000000001"]
    values = {
      id                = "nat-00000000000000001"
      vpc_id            = "vpc-00000000000000001"
      state             = "available"
      connectivity_type = "public"
    }
  }
}

run "use_partition_aware_china_endpoint_names" {
  command = plan

  variables {
    create_vpc                                             = true
    availability_zones                                     = ["cn-north-1a", "cn-north-1b"]
    existing_vpc_id                                        = null
    existing_private_subnet_egress_mode                    = null
    existing_private_vpc_endpoint_ids                      = {}
    existing_private_interface_endpoint_security_group_ids = {}
  }

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws-cn"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "cn-north-1"
    }
  }

  assert {
    condition = (
      local.expected_endpoint_service_names["dynamodb"] ==
      "com.amazonaws.cn-north-1.dynamodb" &&
      local.expected_endpoint_service_names["s3"] ==
      "com.amazonaws.cn-north-1.s3"
    )
    error_message = "China gateway endpoints must retain the com.amazonaws prefix."
  }

  assert {
    condition = (
      local.expected_endpoint_service_names["config"] ==
      "cn.com.amazonaws.cn-north-1.config" &&
      local.expected_endpoint_service_names["ecr.api"] ==
      "cn.com.amazonaws.cn-north-1.ecr.api" &&
      local.expected_endpoint_service_names["eks-auth"] ==
      "cn.com.amazonaws.cn-north-1.eks-auth" &&
      local.expected_endpoint_service_names["sqs"] ==
      "cn.com.amazonaws.cn-north-1.sqs"
    )
    error_message = "China interface endpoints that use cn.com.amazonaws must be mapped per service."
  }

  assert {
    condition = (
      local.expected_endpoint_service_names["logs"] ==
      "com.amazonaws.cn-north-1.logs" &&
      local.expected_endpoint_service_names["secretsmanager"] ==
      "com.amazonaws.cn-north-1.secretsmanager"
    )
    error_message = "China interface endpoints that retain com.amazonaws must be mapped per service."
  }
}

run "reject_incomplete_endpoint_ids" {
  command = plan

  variables {
    existing_private_subnet_egress_mode                    = "vpc_endpoints"
    existing_private_vpc_endpoint_ids                      = {}
    existing_private_interface_endpoint_security_group_ids = {}
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_unavailable_interface_endpoint" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["config"]
    values = {
      vpc_id              = "vpc-00000000000000001"
      state               = "pending"
      service_name        = "com.amazonaws.us-east-1.config"
      vpc_endpoint_type   = "Interface"
      private_dns_enabled = true
      security_group_ids  = ["sg-00000000000000001"]
      route_table_ids     = []
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_endpoint_for_wrong_service" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["config"]
    values = {
      vpc_id              = "vpc-00000000000000001"
      state               = "available"
      service_name        = "com.amazonaws.us-east-1.ec2"
      vpc_endpoint_type   = "Interface"
      private_dns_enabled = true
      security_group_ids  = ["sg-00000000000000001"]
      route_table_ids     = []
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_endpoint_in_another_vpc" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["config"]
    values = {
      vpc_id              = "vpc-00000000000000002"
      state               = "available"
      service_name        = "com.amazonaws.us-east-1.config"
      vpc_endpoint_type   = "Interface"
      private_dns_enabled = true
      security_group_ids  = ["sg-00000000000000001"]
      route_table_ids     = []
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_interface_endpoint_without_private_dns" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["config"]
    values = {
      vpc_id              = "vpc-00000000000000001"
      state               = "available"
      service_name        = "com.amazonaws.us-east-1.config"
      vpc_endpoint_type   = "Interface"
      private_dns_enabled = false
      security_group_ids  = ["sg-00000000000000001"]
      route_table_ids     = []
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_unattached_interface_security_group" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["config"]
    values = {
      vpc_id              = "vpc-00000000000000001"
      state               = "available"
      service_name        = "com.amazonaws.us-east-1.config"
      vpc_endpoint_type   = "Interface"
      private_dns_enabled = true
      security_group_ids  = ["sg-00000000000000002"]
      route_table_ids     = []
    }
  }

  expect_failures = [terraform_data.network_validation]
}

run "reject_gateway_missing_private_route_table" {
  command = plan

  override_data {
    target = data.aws_vpc_endpoint.existing_private["dynamodb"]
    values = {
      vpc_id              = "vpc-00000000000000001"
      state               = "available"
      service_name        = "com.amazonaws.us-east-1.dynamodb"
      vpc_endpoint_type   = "Gateway"
      private_dns_enabled = false
      security_group_ids  = []
      route_table_ids     = ["rtb-00000000000000001"]
    }
  }

  expect_failures = [terraform_data.network_validation]
}
