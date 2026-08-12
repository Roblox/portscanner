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
  description = "Short, portable prefix used for network resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 lowercase alphanumeric or hyphen characters and start with a letter."
  }
}

variable "create_vpc" {
  description = "Create a three-tier VPC when true; otherwise validate and use supplied subnets."
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "Canonical AWS VPC IPv4 CIDR from /16 through /24; four subnet bits are added for the three tiers."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition = (
      can(regex("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}/([0-9]|[12][0-9]|3[0-2])$", var.vpc_cidr)) &&
      can(cidrnetmask(var.vpc_cidr)) &&
      try(cidrhost(var.vpc_cidr, 0) == split("/", var.vpc_cidr)[0], false) &&
      try(tonumber(split("/", var.vpc_cidr)[1]) >= 16, false) &&
      try(tonumber(split("/", var.vpc_cidr)[1]) <= 24, false)
    )
    error_message = "vpc_cidr must be a canonical AWS-valid IPv4 network from /16 through /24."
  }
}

variable "az_count" {
  description = "Number of availability zones for a created VPC."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

variable "availability_zones" {
  description = "Optional explicit availability zones; by default available zones are selected."
  type        = list(string)
  default     = null

  validation {
    condition     = var.availability_zones == null ? true : length(var.availability_zones) >= 2
    error_message = "availability_zones must be null or contain at least two entries."
  }
}

variable "nat_gateway_mode" {
  description = "Use one NAT gateway for low-volume environments or one_per_az for production resilience."
  type        = string
  default     = "single"

  validation {
    condition     = contains(["single", "one_per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be single or one_per_az."
  }
}

variable "existing_vpc_id" {
  description = "Existing VPC ID when create_vpc is false."
  type        = string
  default     = null

  validation {
    condition     = var.existing_vpc_id == null || can(regex("^vpc-[0-9a-f]+$", var.existing_vpc_id))
    error_message = "existing_vpc_id must be null or a valid VPC ID."
  }
}

variable "existing_public_subnet_ids" {
  description = "Optional existing public subnets; these are exposed but never used for EKS, Lambda, or Aurora."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_ids" {
  description = "Existing private subnets for EKS and Lambda when create_vpc is false."
  type        = list(string)
  default     = []
}

variable "existing_isolated_subnet_ids" {
  description = "Existing isolated subnets for Aurora when create_vpc is false."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_egress_mode" {
  description = "Required existing-VPC declaration: nat_gateway, transit_gateway, or vpc_endpoints."
  type        = string
  default     = null

  validation {
    condition = var.existing_private_subnet_egress_mode == null ? true : contains(
      ["nat_gateway", "transit_gateway", "vpc_endpoints"],
      var.existing_private_subnet_egress_mode
    )
    error_message = "existing_private_subnet_egress_mode must be null, nat_gateway, transit_gateway, or vpc_endpoints."
  }
}

variable "scanner_public_egress_required" {
  description = "Reject endpoint-only existing subnets when scanner dispatch is enabled."
  type        = bool
  default     = false
}

variable "existing_public_nat_gateway_ids" {
  description = "Public NAT gateways that every scanner subnet default route must use when existing-VPC scanner dispatch is enabled."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for nat_gateway_id in var.existing_public_nat_gateway_ids :
      can(regex("^nat-[0-9a-f]+$", nat_gateway_id))
    ])
    error_message = "existing_public_nat_gateway_ids must contain valid NAT gateway IDs."
  }
}

variable "existing_transit_gateway_public_egress_acknowledged" {
  description = "Explicit operator attestation that selected TGW default routes are active/non-blackhole and reach reviewed public egress for scanner traffic."
  type        = bool
  default     = false
}

variable "existing_private_vpc_endpoint_ids" {
  description = "Existing VPC endpoint IDs keyed by required AWS service when existing_private_subnet_egress_mode is vpc_endpoints."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for endpoint_id in values(var.existing_private_vpc_endpoint_ids) :
      can(regex("^vpce-[0-9a-f]+$", endpoint_id))
    ])
    error_message = "existing_private_vpc_endpoint_ids values must be valid VPC endpoint IDs."
  }
}

variable "existing_private_interface_endpoint_security_group_ids" {
  description = "One attached security group per required interface endpoint, keyed by service. Terraform adds TCP/443 ingress from the application Lambda and EKS workload security groups."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for security_group_id in values(var.existing_private_interface_endpoint_security_group_ids) :
      can(regex("^sg-[0-9a-f]+$", security_group_id))
    ])
    error_message = "existing_private_interface_endpoint_security_group_ids values must be valid security group IDs."
  }
}

data "aws_availability_zones" "available" {
  count = var.create_vpc && var.availability_zones == null ? 1 : 0
  state = "available"
}

data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  id    = var.existing_vpc_id
}

data "aws_subnet" "existing_private" {
  for_each = var.create_vpc ? toset([]) : toset(var.existing_private_subnet_ids)
  id       = each.value
}

data "aws_subnet" "existing_isolated" {
  for_each = var.create_vpc ? toset([]) : toset(var.existing_isolated_subnet_ids)
  id       = each.value
}

data "aws_subnet" "existing_public" {
  for_each = var.create_vpc ? toset([]) : toset(var.existing_public_subnet_ids)
  id       = each.value
}

data "aws_route_table" "existing_private" {
  for_each  = var.create_vpc ? toset([]) : toset(var.existing_private_subnet_ids)
  subnet_id = each.value
}

data "aws_route_table" "existing_isolated" {
  for_each  = var.create_vpc ? toset([]) : toset(var.existing_isolated_subnet_ids)
  subnet_id = each.value
}

data "aws_vpc_endpoint" "existing_private" {
  for_each = !var.create_vpc && var.existing_private_subnet_egress_mode == "vpc_endpoints" ? var.existing_private_vpc_endpoint_ids : {}

  id = each.value
}

data "aws_nat_gateway" "existing_public" {
  for_each = !var.create_vpc && var.existing_private_subnet_egress_mode == "nat_gateway" ? var.existing_public_nat_gateway_ids : toset([])

  id = each.value
}

locals {
  selected_azs = var.create_vpc ? slice(
    var.availability_zones != null ? var.availability_zones : data.aws_availability_zones.available[0].names,
    0,
    min(
      var.az_count,
      length(var.availability_zones != null ? var.availability_zones : data.aws_availability_zones.available[0].names)
    )
  ) : []
  azs              = { for index, az in local.selected_azs : az => index }
  effective_vpc_id = var.create_vpc ? aws_vpc.this[0].id : data.aws_vpc.existing[0].id
  nat_subnets = length(local.selected_azs) == 0 ? {} : var.nat_gateway_mode == "single" ? {
    primary = local.selected_azs[0]
    } : {
    for az, index in local.azs : az => az
  }
  required_private_endpoint_services = toset([
    "config",
    "dynamodb",
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "eks",
    "eks-auth",
    "logs",
    "s3",
    "secretsmanager",
    "sqs",
    "sts"
  ])
  required_gateway_endpoint_services = toset([
    "dynamodb",
    "s3"
  ])
  required_interface_endpoint_services = setsubtract(
    local.required_private_endpoint_services,
    local.required_gateway_endpoint_services
  )
  china_endpoint_service_prefixes = {
    config         = "cn.com.amazonaws"
    dynamodb       = "com.amazonaws"
    ec2            = "cn.com.amazonaws"
    "ecr.api"      = "cn.com.amazonaws"
    "ecr.dkr"      = "cn.com.amazonaws"
    eks            = "cn.com.amazonaws"
    "eks-auth"     = "cn.com.amazonaws"
    logs           = "com.amazonaws"
    s3             = "com.amazonaws"
    secretsmanager = "com.amazonaws"
    sqs            = "cn.com.amazonaws"
    sts            = "cn.com.amazonaws"
  }
  expected_endpoint_service_names = {
    for service in local.required_private_endpoint_services :
    service => "${
      data.aws_partition.current.partition == "aws-cn" ?
      local.china_endpoint_service_prefixes[service] :
      "com.amazonaws"
    }.${data.aws_region.current.region}.${service}"
  }
  existing_private_route_table_ids = toset([
    for table in values(data.aws_route_table.existing_private) : table.id
  ])
  existing_private_route_nat_gateway_ids = toset(flatten([
    for table in values(data.aws_route_table.existing_private) : [
      for route in table.routes : route.nat_gateway_id
      if route.cidr_block == "0.0.0.0/0" &&
      try(startswith(route.nat_gateway_id, "nat-"), false)
    ]
  ]))
  existing_interface_endpoint_security_group_ids = toset(
    values(var.existing_private_interface_endpoint_security_group_ids)
  )
}

resource "terraform_data" "network_validation" {
  input = var.name_prefix

  lifecycle {
    precondition {
      condition     = !var.create_vpc || length(local.selected_azs) == var.az_count
      error_message = "A created VPC requires at least az_count available or explicitly supplied availability zones."
    }

    precondition {
      condition     = var.create_vpc || var.existing_vpc_id != null
      error_message = "existing_vpc_id must be supplied when create_vpc is false."
    }

    precondition {
      condition = var.create_vpc || try(
        data.aws_vpc.existing[0].enable_dns_support &&
        data.aws_vpc.existing[0].enable_dns_hostnames,
        false
      )
      error_message = "Existing VPCs must enable DNS support and DNS hostnames for AWS service and private EKS endpoint resolution."
    }

    precondition {
      condition = var.create_vpc || (
        length(var.existing_private_subnet_ids) >= 2 &&
        length(var.existing_isolated_subnet_ids) >= 2
      )
      error_message = "Existing mode requires at least two private and two isolated subnets."
    }

    precondition {
      condition     = var.create_vpc || var.existing_private_subnet_egress_mode != null
      error_message = "Existing mode requires existing_private_subnet_egress_mode to declare NAT gateway, transit gateway, or verified VPC endpoint egress."
    }

    precondition {
      condition = (
        !var.scanner_public_egress_required ||
        var.create_vpc ||
        try(contains(["nat_gateway", "transit_gateway"], var.existing_private_subnet_egress_mode), false)
      )
      error_message = "Scanner dispatch requires NAT gateway or transit gateway public egress; VPC endpoints alone cannot reach public scan targets."
    }

    precondition {
      condition = (
        !var.scanner_public_egress_required ||
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "nat_gateway" ||
        (
          length(var.existing_public_nat_gateway_ids) > 0 &&
          local.existing_private_route_nat_gateway_ids == var.existing_public_nat_gateway_ids &&
          alltrue([
            for gateway in values(data.aws_nat_gateway.existing_public) :
            gateway.vpc_id == var.existing_vpc_id &&
            gateway.state == "available" &&
            gateway.connectivity_type == "public"
          ])
        )
      )
      error_message = "NAT scanner egress requires every private default-route NAT ID to be declared and verified as an available public NAT gateway in the selected VPC."
    }

    precondition {
      condition = (
        !var.scanner_public_egress_required ||
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "transit_gateway" ||
        var.existing_transit_gateway_public_egress_acknowledged
      )
      error_message = "Transit-gateway scanner egress requires an explicit reviewed acknowledgement that the TGW path reaches public egress."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "vpc_endpoints" ||
        toset(keys(var.existing_private_vpc_endpoint_ids)) == local.required_private_endpoint_services
      )
      error_message = "VPC endpoint egress requires exactly one endpoint ID for config, DynamoDB, EC2, ECR API/DKR, EKS, EKS Auth, Logs, S3, Secrets Manager, SQS, and STS."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "vpc_endpoints" ||
        toset(keys(var.existing_private_interface_endpoint_security_group_ids)) == local.required_interface_endpoint_services
      )
      error_message = "VPC endpoint egress requires exactly one attached security group for every required interface endpoint."
    }

    precondition {
      condition = (
        !var.create_vpc &&
        var.existing_private_subnet_egress_mode == "vpc_endpoints"
        ) || (
        length(var.existing_private_vpc_endpoint_ids) == 0 &&
        length(var.existing_private_interface_endpoint_security_group_ids) == 0
      )
      error_message = "Existing endpoint IDs and endpoint security groups are valid only for existing-VPC vpc_endpoints egress mode."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "vpc_endpoints" ||
        alltrue([
          for service, endpoint in data.aws_vpc_endpoint.existing_private :
          endpoint.vpc_id == var.existing_vpc_id &&
          endpoint.state == "available" &&
          endpoint.service_name == local.expected_endpoint_service_names[service]
        ])
      )
      error_message = "Every supplied VPC endpoint must be available, belong to existing_vpc_id, and expose the expected regional AWS service."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "vpc_endpoints" ||
        try(alltrue([
          for service in local.required_gateway_endpoint_services :
          data.aws_vpc_endpoint.existing_private[service].vpc_endpoint_type == "Gateway" &&
          length(setsubtract(
            local.existing_private_route_table_ids,
            toset(data.aws_vpc_endpoint.existing_private[service].route_table_ids)
          )) == 0
        ]), false)
      )
      error_message = "S3 and DynamoDB endpoints must be Gateway endpoints associated with every selected private-subnet route table."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode != "vpc_endpoints" ||
        try(alltrue([
          for service in local.required_interface_endpoint_services :
          data.aws_vpc_endpoint.existing_private[service].vpc_endpoint_type == "Interface" &&
          data.aws_vpc_endpoint.existing_private[service].private_dns_enabled &&
          contains(
            data.aws_vpc_endpoint.existing_private[service].security_group_ids,
            var.existing_private_interface_endpoint_security_group_ids[service]
          )
        ]), false)
      )
      error_message = "Every required interface endpoint must have private DNS enabled and include its explicitly selected security group."
    }

    precondition {
      condition = var.create_vpc || alltrue([
        for subnet in concat(
          values(data.aws_subnet.existing_private),
          values(data.aws_subnet.existing_isolated),
          values(data.aws_subnet.existing_public)
        ) : subnet.vpc_id == var.existing_vpc_id
      ])
      error_message = "Every supplied subnet must belong to existing_vpc_id."
    }

    precondition {
      condition = var.create_vpc || (
        length(distinct([for subnet in values(data.aws_subnet.existing_private) : subnet.availability_zone])) >= 2 &&
        length(distinct([for subnet in values(data.aws_subnet.existing_isolated) : subnet.availability_zone])) >= 2
      )
      error_message = "Private and isolated existing subnets must each span at least two availability zones."
    }

    precondition {
      condition = var.create_vpc || alltrue([
        for subnet in concat(
          values(data.aws_subnet.existing_private),
          values(data.aws_subnet.existing_isolated)
        ) : !subnet.map_public_ip_on_launch
      ])
      error_message = "Existing private and isolated subnets must not map public IP addresses."
    }

    precondition {
      condition = var.create_vpc || alltrue(flatten([
        for table in values(data.aws_route_table.existing_private) : [
          for route in table.routes :
          route.cidr_block != "0.0.0.0/0" || try(!startswith(route.gateway_id, "igw-"), true)
        ]
      ]))
      error_message = "Existing private subnets must not route directly to an internet gateway."
    }

    precondition {
      condition = (
        var.create_vpc ||
        var.existing_private_subnet_egress_mode == null ||
        var.existing_private_subnet_egress_mode == "vpc_endpoints" ||
        alltrue([
          for table in values(data.aws_route_table.existing_private) :
          anytrue([
            for route in table.routes :
            route.cidr_block == "0.0.0.0/0" &&
            (
              var.existing_private_subnet_egress_mode == "nat_gateway" ?
              try(startswith(route.nat_gateway_id, "nat-"), false) :
              try(startswith(route.transit_gateway_id, "tgw-"), false)
            )
          ])
        ])
      )
      error_message = "Every existing private subnet must have a matching IPv4 default route through the declared NAT gateway or transit gateway."
    }

    precondition {
      condition = var.create_vpc || alltrue(flatten([
        for table in values(data.aws_route_table.existing_isolated) : [
          for route in table.routes :
          route.cidr_block != "0.0.0.0/0" && route.ipv6_cidr_block != "::/0"
        ]
      ]))
      error_message = "Existing isolated database subnets must not have an IPv4 or IPv6 default route."
    }
  }
}

resource "aws_vpc" "this" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = var.name_prefix
  }
}

resource "aws_internet_gateway" "this" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  for_each = var.create_vpc ? local.azs : {}

  vpc_id                  = aws_vpc.this[0].id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, each.value)
  map_public_ip_on_launch = true

  tags = {
    Name                     = "${var.name_prefix}-public-${each.key}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "private" {
  for_each = var.create_vpc ? local.azs : {}

  vpc_id                  = aws_vpc.this[0].id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, each.value + 4)
  map_public_ip_on_launch = false

  tags = {
    Name                              = "${var.name_prefix}-private-${each.key}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "isolated" {
  for_each = var.create_vpc ? local.azs : {}

  vpc_id                  = aws_vpc.this[0].id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, each.value + 8)
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-isolated-${each.key}"
  }
}

resource "aws_eip" "nat" {
  for_each = var.create_vpc ? local.nat_subnets : {}
  domain   = "vpc"

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  for_each = var.create_vpc ? local.nat_subnets : {}

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.value].id

  tags = {
    Name = "${var.name_prefix}-nat-${each.key}"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_route" "public_internet" {
  count = var.create_vpc ? 1 : 0

  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  for_each = var.create_vpc ? local.azs : {}

  route_table_id = aws_route_table.public[0].id
  subnet_id      = aws_subnet.public[each.key].id
}

resource "aws_route_table" "private" {
  for_each = var.create_vpc ? local.azs : {}
  vpc_id   = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
  }
}

resource "aws_route" "private_nat" {
  for_each = var.create_vpc ? local.azs : {}

  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = var.nat_gateway_mode == "single" ? (
    aws_nat_gateway.this["primary"].id
  ) : aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "private" {
  for_each = var.create_vpc ? local.azs : {}

  route_table_id = aws_route_table.private[each.key].id
  subnet_id      = aws_subnet.private[each.key].id
}

resource "aws_route_table" "isolated" {
  for_each = var.create_vpc ? local.azs : {}
  vpc_id   = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-isolated-${each.key}"
  }
}

resource "aws_route_table_association" "isolated" {
  for_each = var.create_vpc ? local.azs : {}

  route_table_id = aws_route_table.isolated[each.key].id
  subnet_id      = aws_subnet.isolated[each.key].id
}

resource "aws_vpc_endpoint" "s3" {
  count = var.create_vpc ? 1 : 0

  vpc_id            = aws_vpc.this[0].id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = values(aws_route_table.private)[*].id

  tags = {
    Name = "${var.name_prefix}-s3"
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  count = var.create_vpc ? 1 : 0

  vpc_id            = aws_vpc.this[0].id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = values(aws_route_table.private)[*].id

  tags = {
    Name = "${var.name_prefix}-dynamodb"
  }
}

resource "aws_security_group" "lambda_runtime" {
  name_prefix            = "${var.name_prefix}-lambda-runtime-"
  description            = "Private Lambda clients without database network access"
  vpc_id                 = local.effective_vpc_id
  revoke_rules_on_delete = true

  tags = {
    Name = "${var.name_prefix}-lambda-runtime"
  }
}

resource "aws_security_group" "lambda_database" {
  name_prefix            = "${var.name_prefix}-lambda-database-"
  description            = "Private Lambda PostgreSQL clients"
  vpc_id                 = local.effective_vpc_id
  revoke_rules_on_delete = true

  tags = {
    Name = "${var.name_prefix}-lambda-database"
  }
}

resource "aws_vpc_security_group_egress_rule" "lambda_https" {
  for_each = {
    runtime  = aws_security_group.lambda_runtime.id
    database = aws_security_group.lambda_database.id
  }

  security_group_id = each.value
  description       = "TLS to AWS APIs through VPC endpoints or the private-subnet NAT path"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "existing_endpoint_lambda_runtime" {
  for_each = !var.create_vpc && var.existing_private_subnet_egress_mode == "vpc_endpoints" ? local.existing_interface_endpoint_security_group_ids : toset([])

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.lambda_runtime.id
  description                  = "TLS from portscanner runtime Lambdas"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "existing_endpoint_lambda_database" {
  for_each = !var.create_vpc && var.existing_private_subnet_egress_mode == "vpc_endpoints" ? local.existing_interface_endpoint_security_group_ids : toset([])

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.lambda_database.id
  description                  = "TLS from portscanner database Lambdas"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

data "aws_partition" "current" {}
data "aws_region" "current" {}

output "vpc_id" {
  value = var.create_vpc ? aws_vpc.this[0].id : data.aws_vpc.existing[0].id
}

output "public_subnet_ids" {
  value = var.create_vpc ? values(aws_subnet.public)[*].id : var.existing_public_subnet_ids
}

output "private_subnet_ids" {
  value = var.create_vpc ? values(aws_subnet.private)[*].id : var.existing_private_subnet_ids
}

output "isolated_subnet_ids" {
  value = var.create_vpc ? values(aws_subnet.isolated)[*].id : var.existing_isolated_subnet_ids
}

output "created_nat_public_ips" {
  description = "Stable scanner egress addresses for a created VPC. Empty for an existing VPC whose egress is externally managed."
  value       = sort([for address in values(aws_eip.nat) : address.public_ip])
}

output "lambda_runtime_security_group_id" {
  value = aws_security_group.lambda_runtime.id
}

output "lambda_database_security_group_id" {
  value = aws_security_group.lambda_database.id
}

output "existing_interface_endpoint_security_group_ids" {
  description = "Validated interface endpoint security groups that require EKS workload ingress."
  value       = local.existing_interface_endpoint_security_group_ids
}
