mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
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

  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = {
      supported_architectures = ["arm64"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

mock_provider "helm" {}

run "canonical_environment_maps_to_paused_database_first_stack" {
  command = plan

  variables {
    environment = {
      name = "test-eval"
      aws = {
        account_id = "123456789012"
        region     = "us-east-1"
      }
      network = {
        vpc_cidr           = "10.64.0.0/20"
        availability_zones = []
        az_count           = 2
        nat_gateway_mode   = "single"
      }
      runner = {
        eks_installer_principal_arn = "arn:aws:iam::123456789012:role/test-installer"
        restricted_public_cidr      = "203.0.113.10/32"
      }
      retention = {
        disposable               = true
        destroy_data_on_teardown = true
        database_backup_days     = 1
        lambda_log_days          = 7
        ecr_untagged_image_days  = 7
        bucket_expiration_days = {
          events     = 7
          results    = 7
          findings   = 30
          cloudtrail = 30
        }
      }
      scanner = {
        operator_max_concurrent_reconciles = 1
        max_concurrent_pods                = 1
        max_jobs                           = 4
        min_rate                           = 100
        max_rate                           = 250
        architecture                       = "arm64"
        node_instance_type                 = "t4g.medium"
      }
      managed_canary = {
        enabled                   = true
        vpc_cidr                  = "10.255.255.0/28"
        instance_type             = "t4g.nano"
        listen_port               = 18080
        expected_finding_severity = "low"
      }
      integrations = {
        recurring_inventory_enabled     = false
        signal_hints_enabled            = false
        finding_export_enabled          = false
        config_mode                     = "disabled"
        existing_config_aggregator_name = ""
        snapshot_regions                = []
        cloudtrail_mode                 = "disabled"
        existing_cloudtrail_arn         = ""
        authorized_account_ids          = []
        allowed_target_cidrs            = []
        denied_target_cidrs             = []
        allowed_eni_interface_types     = ["interface"]
        required_target_tag_key         = "application"
        required_target_tag_value       = "portscanner"
      }
    }
  }

  assert {
    condition = (
      output.deployment_state.managed_canary_enabled &&
      !output.deployment_state.dispatch_enabled &&
      output.managed_canary.listener_port == 18080 &&
      output.finding_bucket_name == null &&
      output.finding_queue_url == null &&
      output.operator_namespace == "portscanner-system" &&
      length(output.retirement_configuration_fingerprint) == 64
    )
    error_message = "The canonical environment must plan a paused managed canary and database-only finding boundary."
  }
}
