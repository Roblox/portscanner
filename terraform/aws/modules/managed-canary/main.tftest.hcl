mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }
}

variables {
  name_prefix = "test-scan"
  scanner_source_ipv4_cidrs = [
    "198.51.100.10/32",
    "203.0.113.20/32",
  ]
}

run "creates_isolated_minimal_target" {
  command = plan

  assert {
    condition = (
      aws_subnet.public.map_public_ip_on_launch == false &&
      aws_route.internet.destination_cidr_block == "0.0.0.0/0" &&
      length(aws_vpc_security_group_ingress_rule.scanner) == 2
    )
    error_message = "The canary must use its own public subnet and one ingress rule per scanner NAT EIP."
  }

  assert {
    condition = alltrue([
      for rule in aws_vpc_security_group_ingress_rule.scanner :
      rule.from_port == 18080 &&
      rule.to_port == 18080 &&
      rule.ip_protocol == "tcp"
    ])
    error_message = "The managed canary must expose only TCP 18080."
  }

  assert {
    condition = (
      length(aws_security_group.listener.egress) == 0 &&
      aws_instance.this.metadata_options[0].http_tokens == "required" &&
      aws_instance.this.metadata_options[0].http_put_response_hop_limit == 1 &&
      aws_instance.this.root_block_device[0].encrypted &&
      aws_instance.this.root_block_device[0].volume_type == "gp3"
    )
    error_message = "The target must have no egress, require IMDSv2, and use an encrypted root disk."
  }

  assert {
    condition = (
      aws_network_interface.this.tags["service"] == "test-scan-managed-canary" &&
      output.listener_port == 18080 &&
      output.inventory_tag_key == "service" &&
      output.inventory_tag_value == "test-scan-managed-canary"
    )
    error_message = "Inventory must receive a deterministic managed-canary identity."
  }
}

run "rejects_missing_scanner_nat_scope" {
  command = plan

  variables {
    scanner_source_ipv4_cidrs = []
  }

  expect_failures = [terraform_data.validation]
}

run "rejects_non_exact_scanner_scope" {
  command = plan

  variables {
    scanner_source_ipv4_cidrs = ["198.51.100.0/24"]
  }

  expect_failures = [var.scanner_source_ipv4_cidrs]
}
