// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
)

func TestSharedTargetEventReachesEveryScannerInput(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	pythonPath := strings.Join(
		[]string{
			filepath.Join(repositoryRoot, "contracts", "src"),
			filepath.Join(repositoryRoot, "generator", "src"),
		},
		string(os.PathListSeparator),
	)
	pythonExecutable := os.Getenv("PORTSCANNER_TEST_PYTHON")
	if pythonExecutable == "" {
		pythonExecutable = "python3"
	}
	probe := exec.Command(
		pythonExecutable,
		"-c",
		"import sys, pydantic; assert sys.version_info >= (3, 12)",
	)
	if output, err := probe.CombinedOutput(); err != nil {
		t.Skipf("shared-contract Python dependencies are unavailable: %v: %s", err, output)
	}

	const buildResource = `
import json
from datetime import UTC, datetime, timedelta

from portscanner_contracts import (
    AddressFamily,
    AwsContext,
    AwsTags,
    CloudProvider,
    FULL_TCP_PORT_RANGE,
    ScanDirective,
    ScanProfile,
    ScanReason,
    SourceObservation,
    Target,
    TargetEvent,
    TargetEventType,
    TransportProtocol,
)
from portscanner_generator.scanner_resource import build_scanner_resource

observed = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
target = Target.create(
    provider=CloudProvider.AWS,
    scope_id="123456789012",
    location="us-east-1",
    resource_id="eni-0123456789abcdef0",
    private_address="10.0.0.10",
    public_address="198.51.100.25",
    address_family=AddressFamily.IPV4,
    transport=TransportProtocol.TCP,
    generation=7,
)
source = SourceObservation.create(
    source_event_name="AwsConfigSnapshot",
    source_event_id="source-event-1",
    source_request_id="source-request-1",
    event_time=observed - timedelta(seconds=30),
    observed_at=observed,
    collected_at=observed + timedelta(seconds=30),
)
context = AwsContext(
    account_id=target.scope_id,
    region=target.location,
    network_interface_id=target.resource_id,
    private_ip=target.private_address,
    public_ip=target.public_address,
    instance_id="i-0123456789abcdef0",
    security_group_ids=("sg-0123456789abcdef0",),
    policy_fingerprint="4" * 64,
    candidate_tcp_port_ranges=(FULL_TCP_PORT_RANGE,),
    source_event_name=source.source_event_name,
    source_event_id=source.source_event_id,
    source_request_id=source.source_request_id,
    tags=AwsTags(),
)
directive = ScanDirective.create(
    target_id=target.target_id,
    target_generation=target.generation,
    reason=ScanReason.TARGET_CHANGE,
    profile=ScanProfile.FAST_FULL_TCP,
    priority=800,
    requested_at=observed + timedelta(minutes=1),
    deadline_at=observed + timedelta(minutes=6),
    not_after=observed + timedelta(minutes=11),
    tcp_port_ranges=(FULL_TCP_PORT_RANGE,),
)
event = TargetEvent.create(
    schema_version="1.0",
    event_type=TargetEventType.TARGET_UPSERT,
    target=target,
    source=source,
    policy_change=None,
    scan=directive,
    aws_context=context,
)
print(json.dumps(build_scanner_resource(event, namespace="integration")))
`
	command := exec.Command(pythonExecutable, "-c", buildResource)
	command.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	encoded, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build generator Scanner from shared TargetEvent: %v\n%s", err, encoded)
	}

	var scanner scanningv1alpha1.Scanner
	if err := json.Unmarshal(encoded, &scanner); err != nil {
		t.Fatalf("deserialize generator Scanner as operator API: %v\n%s", err, encoded)
	}
	now := time.Date(2030, time.January, 2, 3, 5, 5, 0, time.UTC)
	config := validJobConfig()
	job, err := buildJob(&scanner, config, now)
	if err != nil {
		t.Fatalf("build scanner Job: %v", err)
	}

	container := job.Spec.Template.Spec.Containers[0]
	staticEnv := make(map[string]string)
	fieldRefs := make(map[string]string)
	for _, variable := range container.Env {
		staticEnv[variable.Name] = variable.Value
		if variable.ValueFrom != nil && variable.ValueFrom.FieldRef != nil {
			fieldRefs[variable.Name] = variable.ValueFrom.FieldRef.FieldPath
		}
	}
	expected := map[string]string{
		"PORTSCANNER_EVENT_ID":               scanner.Spec.EventID,
		"PORTSCANNER_DIRECTIVE_ID":           scanner.Spec.DirectiveID,
		"PORTSCANNER_TRACE_ID":               scanner.Spec.TraceID,
		"PORTSCANNER_REASON":                 string(scanner.Spec.Reason),
		"PORTSCANNER_TARGET_ID":              scanner.Spec.Target.TargetID,
		"PORTSCANNER_TARGET_PROVIDER":        scanner.Spec.Target.Provider,
		"PORTSCANNER_TARGET_SCOPE_ID":        scanner.Spec.Target.ScopeID,
		"PORTSCANNER_TARGET_LOCATION":        scanner.Spec.Target.Location,
		"PORTSCANNER_TARGET_RESOURCE_ID":     scanner.Spec.Target.ResourceID,
		"PORTSCANNER_TARGET_PRIVATE_ADDRESS": scanner.Spec.Target.PrivateAddress,
		"PORTSCANNER_TARGET_GENERATION":      "7",
		"PORTSCANNER_IMAGE_VERSION":          config.ScannerImage,
		"PORTSCANNER_DEADLINE_AT":            scanner.Spec.Deadline.UTC().Format(time.RFC3339Nano),
		"PORTSCANNER_NOT_AFTER":              scanner.Spec.NotAfter.UTC().Format(time.RFC3339Nano),
		"PORTSCANNER_RESULT_BUCKET":          config.ResultBucket,
		"PORTSCANNER_RESULT_PREFIX":          config.ResultPrefix,
	}
	for name, want := range expected {
		if got := staticEnv[name]; got != want || got == "" {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if fieldRefs["PORTSCANNER_RUN_ID"] !=
		"metadata.labels['batch.kubernetes.io/job-name']" {
		t.Errorf("run ID fieldRef = %q", fieldRefs["PORTSCANNER_RUN_ID"])
	}
	if fieldRefs["PORTSCANNER_ATTEMPT_ID"] != "metadata.uid" {
		t.Errorf("attempt ID fieldRef = %q", fieldRefs["PORTSCANNER_ATTEMPT_ID"])
	}

	arguments := strings.Join(container.Args, "\n")
	for _, required := range []string{
		"--target=" + scanner.Spec.Target.Address,
		"--profile=" + string(scanner.Spec.Profile),
		"--tcp-ports=1-65535",
	} {
		if !strings.Contains(arguments, required) {
			t.Errorf("scanner arguments do not contain %q: %#v", required, container.Args)
		}
	}
}
