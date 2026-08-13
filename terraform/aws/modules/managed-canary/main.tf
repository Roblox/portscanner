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
  description = "Portable prefix for the isolated managed canary."
  type        = string
}

variable "vpc_cidr" {
  description = "Dedicated unpeered canary VPC and public-subnet CIDR."
  type        = string
  default     = "10.255.255.0/28"

  validation {
    condition = (
      can(cidrnetmask(var.vpc_cidr)) &&
      try(cidrhost(var.vpc_cidr, 0) == split("/", var.vpc_cidr)[0], false) &&
      try(tonumber(split("/", var.vpc_cidr)[1]) == 28, false)
    )
    error_message = "vpc_cidr must be a canonical IPv4 /28."
  }
}

variable "scanner_source_ipv4_cidrs" {
  description = "Exact scanner NAT EIP /32s allowed to reach the canary listener."
  type        = list(string)

  validation {
    condition = alltrue([
      for cidr in var.scanner_source_ipv4_cidrs :
      cidr != "0.0.0.0/0" &&
      can(cidrnetmask(cidr)) &&
      try(tonumber(split("/", cidr)[1]) == 32, false) &&
      try(cidrhost(cidr, 0) == split("/", cidr)[0], false)
    ])
    error_message = "scanner_source_ipv4_cidrs must contain only canonical IPv4 /32s."
  }
}

variable "instance_type" {
  description = "Small ARM instance type used only for the harmless listener."
  type        = string
  default     = "t4g.nano"
}

variable "listener_port" {
  description = "Single TCP port exposed by the managed canary."
  type        = number
  default     = 18080

  validation {
    condition     = var.listener_port == 18080
    error_message = "The managed canary listener is intentionally fixed to TCP 18080."
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  inventory_tag_key   = "service"
  inventory_tag_value = "${var.name_prefix}-managed-canary"
  canary_tags = {
    Name        = "${var.name_prefix}-managed-canary"
    application = "portscanner"
    service     = local.inventory_tag_value
  }
}

resource "terraform_data" "validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition     = length(var.scanner_source_ipv4_cidrs) > 0
      error_message = "At least one scanner NAT EIP /32 is required for the managed canary."
    }

    precondition {
      condition     = length(data.aws_availability_zones.available.names) > 0
      error_message = "The managed canary requires one available availability zone."
    }
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = false
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-managed-canary"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-managed-canary"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = var.vpc_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-managed-canary"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-managed-canary"
  }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public.id
}

resource "aws_security_group" "listener" {
  name_prefix            = "${substr(var.name_prefix, 0, 28)}-canary-"
  description            = "Managed canary listener with no outbound rules"
  vpc_id                 = aws_vpc.this.id
  revoke_rules_on_delete = true
  egress                 = []

  tags = {
    Name = "${var.name_prefix}-managed-canary"
  }
}

resource "aws_vpc_security_group_ingress_rule" "scanner" {
  count = length(var.scanner_source_ipv4_cidrs)

  security_group_id = aws_security_group.listener.id
  description       = "TCP 18080 from scanner NAT EIP"
  cidr_ipv4         = var.scanner_source_ipv4_cidrs[count.index]
  from_port         = var.listener_port
  to_port           = var.listener_port
  ip_protocol       = "tcp"
}

resource "aws_network_interface" "this" {
  subnet_id         = aws_subnet.public.id
  security_groups   = [aws_security_group.listener.id]
  source_dest_check = true

  tags = local.canary_tags
}

resource "aws_instance" "this" {
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type

  network_interface {
    network_interface_id = aws_network_interface.this.id
    device_index         = 0
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
  }

  instance_initiated_shutdown_behavior = "stop"
  monitoring                           = false
  user_data_replace_on_change          = true
  user_data                            = <<-USER_DATA
    #!/bin/bash
    set -euo pipefail

    cat >/usr/local/bin/portscanner-canary.py <<'PYTHON'
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"portscanner managed canary\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return


    ThreadingHTTPServer(("0.0.0.0", ${var.listener_port}), Handler).serve_forever()
    PYTHON
    chmod 0755 /usr/local/bin/portscanner-canary.py

    cat >/etc/systemd/system/portscanner-canary.service <<'UNIT'
    [Unit]
    Description=Portscanner managed canary HTTP listener
    After=network.target

    [Service]
    Type=simple
    ExecStart=/usr/bin/python3 /usr/local/bin/portscanner-canary.py
    Restart=always
    RestartSec=2
    DynamicUser=yes
    NoNewPrivileges=yes
    PrivateDevices=yes
    ProtectHome=yes
    ProtectSystem=strict

    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl daemon-reload
    systemctl enable --now portscanner-canary.service
  USER_DATA

  tags        = local.canary_tags
  volume_tags = local.canary_tags

  depends_on = [
    aws_route_table_association.public,
    terraform_data.validation,
  ]
}

resource "aws_eip" "this" {
  domain = "vpc"

  tags = {
    Name        = "${var.name_prefix}-managed-canary"
    application = "portscanner"
    service     = local.inventory_tag_value
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_eip_association" "this" {
  allocation_id        = aws_eip.this.id
  network_interface_id = aws_network_interface.this.id

  depends_on = [aws_instance.this]
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_id" {
  value = aws_subnet.public.id
}

output "security_group_id" {
  value = aws_security_group.listener.id
}

output "eip_allocation_id" {
  value = aws_eip.this.allocation_id
}

output "public_ip" {
  value = aws_eip.this.public_ip
}

output "public_cidr" {
  value = "${aws_eip.this.public_ip}/32"
}

output "network_interface_id" {
  value = aws_network_interface.this.id
}

output "private_ip" {
  value = aws_network_interface.this.private_ip
}

output "instance_id" {
  value = aws_instance.this.id
}

output "instance_state" {
  value = aws_instance.this.instance_state
}

output "listener_port" {
  value = var.listener_port
}

output "inventory_tag_key" {
  value = local.inventory_tag_key
}

output "inventory_tag_value" {
  value = local.inventory_tag_value
}
