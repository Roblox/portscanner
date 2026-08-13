#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd -P)"
EVALUATE="${ROOT}/terraform/aws/scripts/evaluate-canary.sh"
RETIRE="${ROOT}/terraform/aws/scripts/retire-canary.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/portscanner-canary-helper-tests.XXXXXX")"
cleanup() {
  rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_config() {
  local enabled="$1"
  cat >"${WORK_DIR}/environment.auto.tfvars.json" <<EOF
{
  "environment": {
    "name": "test-eval",
    "aws": {"account_id": "123456789012", "region": "us-east-1"},
    "network": {
      "vpc_cidr": "10.64.0.0/20",
      "availability_zones": [],
      "az_count": 2,
      "nat_gateway_mode": "single"
    },
    "runner": {
      "eks_installer_principal_arn": "arn:aws:iam::123456789012:role/test-installer",
      "restricted_public_cidr": "203.0.113.10/32"
    },
    "retention": {
      "disposable": true,
      "destroy_data_on_teardown": true,
      "database_backup_days": 1,
      "lambda_log_days": 7,
      "ecr_untagged_image_days": 7,
      "bucket_expiration_days": {
        "events": 7,
        "results": 7,
        "findings": 30,
        "cloudtrail": 30
      }
    },
    "scanner": {
      "operator_max_concurrent_reconciles": 1,
      "max_concurrent_pods": 1,
      "max_jobs": 4,
      "min_rate": 100,
      "max_rate": 250,
      "architecture": "arm64",
      "node_instance_type": "t4g.medium"
    },
    "managed_canary": {
      "enabled": ${enabled},
      "vpc_cidr": "10.255.255.0/28",
      "instance_type": "t4g.nano",
      "listen_port": 18080,
      "expected_finding_severity": "low"
    },
    "integrations": {
      "recurring_inventory_enabled": false,
      "signal_hints_enabled": false,
      "finding_export_enabled": false,
      "config_mode": "disabled",
      "existing_config_aggregator_name": "",
      "snapshot_regions": [],
      "cloudtrail_mode": "disabled",
      "existing_cloudtrail_arn": "",
      "authorized_account_ids": [],
      "allowed_target_cidrs": [],
      "denied_target_cidrs": [],
      "allowed_eni_interface_types": ["interface"],
      "required_target_tag_key": "application",
      "required_target_tag_value": "portscanner"
    }
  }
}
EOF
}

mkdir -p "${WORK_DIR}/root" "${WORK_DIR}/bin"
touch "${WORK_DIR}/root/main.tf" "${WORK_DIR}/backend.hcl" "${WORK_DIR}/images.tfvars"
chmod 600 "${WORK_DIR}/backend.hcl" "${WORK_DIR}/images.tfvars"

cat >"${WORK_DIR}/bin/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
command_name="${2:-}"
case "${command_name}" in
  output)
    format="${3:-}"
    name="${4:-}"
    if [[ "${format}" == "-json" ]]; then
      case "${name}" in
        deployment_state)
          if [[ -f "${FAKE_APPLIED:-/nonexistent}" ]]; then
            printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":false,"canary_mode":false}'
          elif [[ "${FAKE_RETIRE_MODE:-false}" == "true" ]]; then
            printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":false,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":true}'
          else
            printf '%s\n' '{"runtime_created":true,"migration_run":true,"operator_installed":true,"dispatch_enabled":true,"automatic_inventory_enabled":false,"periodic_snapshots_enabled":false,"periodic_coverage_enabled":false,"signal_hints_enabled":false,"processor_reconciliation_enabled":false,"finding_export_enabled":false,"managed_canary_enabled":true,"canary_mode":true}'
          fi
          ;;
        managed_canary)
          if [[ -f "${FAKE_APPLIED:-/nonexistent}" ]]; then
            printf '%s\n' 'null'
          else
            printf '%s\n' '{"account_id":"123456789012","region":"us-east-1","network_interface_id":"eni-0123456789abcdef0","instance_id":"i-0123456789abcdef0","instance_state":"running","public_ip":"203.0.113.20","public_cidr":"203.0.113.20/32","listener_port":18080,"inventory_tag_key":"service","inventory_tag_value":"test-eval-managed-canary"}'
          fi
          ;;
        managed_canary_snapshot_invocation)
          printf '%s\n' '{"function_name":"test-snapshot","function_arn":"arn:aws:lambda:us-east-1:123456789012:function:test-snapshot","payload":{"operation":"managed-canary"}}'
          ;;
        managed_canary_status_invocation)
          printf '%s\n' '{"function_name":"test-processor","function_arn":"arn:aws:lambda:us-east-1:123456789012:function:test-processor","payload":{"operation":"managed-canary-status"}}'
          ;;
        queue_urls)
          printf '%s\n' '{"priority":"https://sqs.us-east-1.amazonaws.com/123456789012/priority","result":"https://sqs.us-east-1.amazonaws.com/123456789012/result"}'
          ;;
        *)
          exit 90
          ;;
      esac
    elif [[ "${format}" == "-raw" ]]; then
      case "${name}" in
        retirement_configuration_fingerprint)
          printf '%064d\n' 0
          ;;
        eks_cluster_name)
          printf '%s\n' 'test-cluster'
          ;;
        operator_namespace)
          printf '%s\n' 'portscanner-system'
          ;;
        *)
          exit 91
          ;;
      esac
    else
      exit 92
    fi
    ;;
  init)
    ;;
  plan)
    for argument in "$@"; do
      case "${argument}" in
        -out=*)
          : >"${argument#-out=}"
          ;;
      esac
    done
    ;;
  show)
    if [[ "${3:-}" == "-json" ]]; then
      fingerprint="$(printf '%064d' 0)"
      [[ "${FAKE_FINGERPRINT_MISMATCH:-false}" != "true" ]] || fingerprint="$(printf '%064d' 1)"
      cat <<JSON
{
  "resource_changes": [
    {
      "mode": "managed",
      "address": "terraform_data.canonical_configuration",
      "change": {"actions": ["update"]}
    },
    {
      "mode": "managed",
      "address": "module.portscanner.module.managed_canary[0].aws_instance.this",
      "change": {"actions": ["delete"]}
    },
    {
      "mode": "managed",
      "address": "module.portscanner.module.managed_canary[0].aws_eip.this",
      "change": {"actions": ["delete"]}
    }
  ],
  "planned_values": {
    "outputs": {
      "retirement_configuration_fingerprint": {"value": "${fingerprint}"},
      "deployment_state": {
        "value": {
          "managed_canary_enabled": false,
          "canary_mode": false,
          "dispatch_enabled": false,
          "automatic_inventory_enabled": false,
          "periodic_snapshots_enabled": false,
          "periodic_coverage_enabled": false,
          "signal_hints_enabled": false,
          "processor_reconciliation_enabled": false
        }
      }
    }
  }
}
JSON
    else
      echo "retirement plan"
    fi
    ;;
  apply)
    : >"${FAKE_APPLIED:?}"
    ;;
  *)
    echo "unexpected terraform invocation: $*" >&2
    exit 93
    ;;
esac
EOF
chmod 755 "${WORK_DIR}/bin/terraform"

cat >"${WORK_DIR}/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-} ${2:-}" in
  "sts get-caller-identity")
    printf '%s\n' '123456789012'
    ;;
  "lambda invoke")
    function_name=""
    previous=""
    for argument in "$@"; do
      if [[ "${previous}" == "--function-name" ]]; then
        function_name="${argument}"
      fi
      previous="${argument}"
    done
    response_file="${!#}"
    if [[ "${function_name}" == "test-snapshot" ]]; then
      printf '%s\n' '[{"completion":"complete","targets":1,"pages":1,"revalidated":0,"added":1,"changed":0,"noop":0,"removed":0,"race":0}]' >"${response_file}"
    elif [[ "${function_name}" == "test-processor" ]]; then
      attempt_count=1
      [[ "${FAKE_DUPLICATE_STATUS:-false}" != "true" ]] || attempt_count=2
      printf '{"operation":"managed-canary-status","status":"ready","ready":true,"target_count":1,"event_count":1,"attempt_count":%s,"complete_coverage_count":1,"open_exposure_count":1,"low_finding_count":1,"unexpected_high_finding_count":0}\n' "${attempt_count}" >"${response_file}"
    else
      exit 80
    fi
    printf '%s\n' '{"StatusCode":200}'
    ;;
  "sqs get-queue-attributes")
    printf '%s\n' '{"ApproximateNumberOfMessages":"0","ApproximateNumberOfMessagesNotVisible":"0","ApproximateNumberOfMessagesDelayed":"0"}'
    ;;
  "eks update-kubeconfig")
    previous=""
    for argument in "$@"; do
      if [[ "${previous}" == "--kubeconfig" ]]; then
        printf '%s\n' 'apiVersion: v1' >"${argument}"
      fi
      previous="${argument}"
    done
    ;;
  *)
    echo "unexpected aws invocation: $*" >&2
    exit 81
    ;;
esac
EOF
chmod 755 "${WORK_DIR}/bin/aws"

cat >"${WORK_DIR}/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" get jobs "* ]]; then
  printf '%s\n' '{"items":[{"status":{"active":0,"conditions":[{"type":"Complete","status":"True"}]}}]}'
elif [[ " $* " == *" get scanners.scanning.portscanner.io "* ]]; then
  printf '%s\n' '{"items":[{"status":{"outcome":"Succeeded"}}]}'
else
  exit 70
fi
EOF
chmod 755 "${WORK_DIR}/bin/kubectl"

write_config true
PATH="${WORK_DIR}/bin:${PATH}" \
PORTSCANNER_CANARY_TIMEOUT_SECONDS=60 \
PORTSCANNER_CANARY_POLL_SECONDS=0 \
PORTSCANNER_CANARY_STABILITY_POLLS=1 \
  "${EVALUATE}" \
    --terraform-root "${WORK_DIR}/root" \
    --environment-config "${WORK_DIR}/environment.auto.tfvars.json" \
    --backend-config "${WORK_DIR}/backend.hcl" \
    --image-inputs "${WORK_DIR}/images.tfvars" \
    >"${WORK_DIR}/evaluate.out"
[[ "$(<"${WORK_DIR}/evaluate.out")" == *"Managed canary verified"* ]] ||
  fail "successful evaluation did not report verification"

if PATH="${WORK_DIR}/bin:${PATH}" \
  FAKE_DUPLICATE_STATUS=true \
  PORTSCANNER_CANARY_TIMEOUT_SECONDS=60 \
  PORTSCANNER_CANARY_POLL_SECONDS=0 \
  PORTSCANNER_CANARY_STABILITY_POLLS=1 \
  "${EVALUATE}" \
    --terraform-root "${WORK_DIR}/root" \
    --environment-config "${WORK_DIR}/environment.auto.tfvars.json" \
    --backend-config "${WORK_DIR}/backend.hcl" \
    --image-inputs "${WORK_DIR}/images.tfvars" \
    >"${WORK_DIR}/duplicate.out" 2>"${WORK_DIR}/duplicate.err"; then
  fail "evaluation accepted a duplicate effective attempt"
fi
[[ "$(<"${WORK_DIR}/duplicate.err")" == *"non-idempotent"* ]] ||
  fail "duplicate evaluation failure was not explicit"

PATH="${WORK_DIR}/bin:${PATH}" \
FAKE_RETIRE_MODE=true \
PORTSCANNER_RETIRE_QUEUE_POLLS=2 \
PORTSCANNER_RETIRE_QUEUE_POLL_SECONDS=0 \
  "${RETIRE}" \
    --verify-only \
    --terraform-root "${WORK_DIR}/root" \
    --environment-config "${WORK_DIR}/environment.auto.tfvars.json" \
    --backend-config "${WORK_DIR}/backend.hcl" \
    --image-inputs "${WORK_DIR}/images.tfvars" \
    >"${WORK_DIR}/verify-only.out"
[[ "$(<"${WORK_DIR}/verify-only.out")" == *"Retirement readiness verified"* ]] ||
  fail "verify-only retirement readiness did not complete"

write_config false
FAKE_APPLIED="${WORK_DIR}/applied"
export FAKE_APPLIED
PATH="${WORK_DIR}/bin:${PATH}" \
FAKE_RETIRE_MODE=true \
PORTSCANNER_AUTO_APPROVE=true \
PORTSCANNER_RETIRE_QUEUE_POLLS=2 \
PORTSCANNER_RETIRE_QUEUE_POLL_SECONDS=0 \
  "${RETIRE}" \
    --terraform-root "${WORK_DIR}/root" \
    --environment-config "${WORK_DIR}/environment.auto.tfvars.json" \
    --backend-config "${WORK_DIR}/backend.hcl" \
    --image-inputs "${WORK_DIR}/images.tfvars" \
    >"${WORK_DIR}/retire.out"
[[ "$(<"${WORK_DIR}/retire.out")" == *"Managed canary retired"* ]] ||
  fail "successful retirement did not report completion"

rm -f "${FAKE_APPLIED}"
if PATH="${WORK_DIR}/bin:${PATH}" \
  FAKE_RETIRE_MODE=true \
  FAKE_FINGERPRINT_MISMATCH=true \
  PORTSCANNER_AUTO_APPROVE=true \
  PORTSCANNER_RETIRE_QUEUE_POLLS=2 \
  PORTSCANNER_RETIRE_QUEUE_POLL_SECONDS=0 \
  "${RETIRE}" \
    --terraform-root "${WORK_DIR}/root" \
    --environment-config "${WORK_DIR}/environment.auto.tfvars.json" \
    --backend-config "${WORK_DIR}/backend.hcl" \
    --image-inputs "${WORK_DIR}/images.tfvars" \
    >"${WORK_DIR}/fingerprint.out" 2>"${WORK_DIR}/fingerprint.err"; then
  fail "retirement accepted an unrelated environment change"
fi
[[ "$(<"${WORK_DIR}/fingerprint.err")" == *"other than managed_canary.enabled"* ]] ||
  fail "retirement fingerprint failure was not explicit"

echo "canary helper tests passed"
