mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
}

variables {
  name_prefix = "test-network"
  create_vpc  = true
  vpc_cidr    = "10.20.0.0/24"
  availability_zones = [
    "us-east-1a",
    "us-east-1b"
  ]
  az_count = 2
}

run "created_vpc_adds_four_subnet_bits" {
  command = plan

  assert {
    condition     = aws_subnet.public["us-east-1a"].cidr_block == "10.20.0.0/28"
    error_message = "Public subnets must derive a valid /28 from a /24 VPC."
  }

  assert {
    condition     = aws_subnet.private["us-east-1a"].cidr_block == "10.20.0.64/28"
    error_message = "Private subnets must occupy the second subnet tier."
  }

  assert {
    condition     = aws_subnet.isolated["us-east-1a"].cidr_block == "10.20.0.128/28"
    error_message = "Isolated subnets must occupy the third subnet tier."
  }
}

run "reject_noncanonical_vpc_cidr" {
  command = plan

  variables {
    vpc_cidr = "10.20.0.1/24"
  }

  expect_failures = [var.vpc_cidr]
}

run "reject_vpc_cidr_too_narrow_for_subnets" {
  command = plan

  variables {
    vpc_cidr = "10.20.0.0/25"
  }

  expect_failures = [var.vpc_cidr]
}

run "reject_vpc_cidr_larger_than_aws_limit" {
  command = plan

  variables {
    vpc_cidr = "10.0.0.0/15"
  }

  expect_failures = [var.vpc_cidr]
}
