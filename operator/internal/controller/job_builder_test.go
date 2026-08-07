// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestScannerArgumentsMapProfilesAndCoverage(t *testing.T) {
	tests := []struct {
		name    string
		profile scanningv1alpha1.ScanProfile
		ports   []int32
		ranges  []scanningv1alpha1.PortRange
		want    []string
		wantErr bool
	}{
		{
			name:    "fast full tcp is always explicit",
			profile: scanningv1alpha1.ProfileFastFullTCP,
			want: []string{
				"--target=192.0.2.10",
				"--profile=fast-full-tcp",
				"--tcp-ports=1-65535",
				"--scan-mode=fast",
			},
		},
		{
			name:    "targeted ports are normalized",
			profile: scanningv1alpha1.ProfileTargetedTCP,
			ports:   []int32{443, 80, 81, 443},
			ranges:  []scanningv1alpha1.PortRange{{Start: 82, End: 84}},
			want: []string{
				"--target=192.0.2.10",
				"--profile=targeted-tcp",
				"--tcp-ports=80-84,443",
				"--scan-mode=targeted",
			},
		},
		{
			name:    "deep defaults to full coverage",
			profile: scanningv1alpha1.ProfileDeep,
			want: []string{
				"--target=192.0.2.10",
				"--profile=deep",
				"--tcp-ports=1-65535",
				"--scan-mode=deep",
				"--service-detection",
			},
		},
		{
			name:    "targeted requires coverage",
			profile: scanningv1alpha1.ProfileTargetedTCP,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validScanner(time.Now().UTC()).Spec
			spec.Profile = test.profile
			spec.Ports = test.ports
			spec.Ranges = test.ranges
			got, err := scannerArguments(spec)
			if test.wantErr {
				if err == nil {
					t.Fatal("scannerArguments() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("scannerArguments() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("scannerArguments() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestActiveDeadlineUsesAbsoluteNotAfterCutoff(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	spec := validScanner(now).Spec
	spec.Deadline = metav1.NewTime(now.Add(90 * time.Second))
	spec.NotAfter = metav1.NewTime(now.Add(10 * time.Minute))

	got, err := activeDeadlineSeconds(spec, now)
	if err != nil {
		t.Fatalf("activeDeadlineSeconds() error = %v", err)
	}
	if got != 600 {
		t.Fatalf("activeDeadlineSeconds() = %d, want 600", got)
	}

	spec.NotAfter = metav1.NewTime(now)
	if _, err := activeDeadlineSeconds(spec, now); err == nil {
		t.Fatal("activeDeadlineSeconds() accepted an expired request")
	}
}

func TestPriorityMapping(t *testing.T) {
	config := validJobConfig()
	config.HighPriorityThreshold = 700

	if got := priorityClassName(699, config); got != "normal-scans" {
		t.Fatalf("priorityClassName(699) = %q, want normal-scans", got)
	}
	if got := priorityClassName(700, config); got != "high-scans" {
		t.Fatalf("priorityClassName(700) = %q, want high-scans", got)
	}
}

func TestBuildJobSecurityContextAndCorrelation(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	config := validJobConfig()

	job, err := buildJob(scanner, config, now)
	if err != nil {
		t.Fatalf("buildJob() error = %v", err)
	}
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != scanner.Spec.RetryLimit {
		t.Fatal("retryLimit was not mapped to Job backoffLimit")
	}
	if job.Spec.TTLSecondsAfterFinished == nil ||
		*job.Spec.TTLSecondsAfterFinished != scanner.Spec.TTLSecondsAfterFinished {
		t.Fatal("TTL control was not mapped to the Job")
	}
	if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 600 {
		t.Fatalf("activeDeadlineSeconds = %v, want 600 from notAfter", job.Spec.ActiveDeadlineSeconds)
	}
	if !safeIdentifierPattern.MatchString(job.Name) {
		t.Fatalf("Job-derived run ID %q is not scanner-safe", job.Name)
	}
	if job.Spec.Template.Labels["batch.kubernetes.io/job-name"] != job.Name {
		t.Fatal("Pod template Job-name label does not match the run ID")
	}
	pod := job.Spec.Template.Spec
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("RestartPolicy = %q, want Never", pod.RestartPolicy)
	}
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Fatal("pod must run as non-root")
	}
	if pod.SecurityContext.SeccompProfile == nil ||
		pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("pod must use RuntimeDefault seccomp")
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("scanner service account token must not be mounted")
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(pod.Containers))
	}
	container := pod.Containers[0]
	security := container.SecurityContext
	if security == nil || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation {
		t.Fatal("container must disallow privilege escalation")
	}
	if security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem {
		t.Fatal("container root filesystem must be read-only")
	}
	if security.Privileged != nil && *security.Privileged {
		t.Fatal("scanner container must not use Kubernetes privileged mode")
	}
	if !reflect.DeepEqual(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Fatalf("dropped capabilities = %#v, want ALL", security.Capabilities.Drop)
	}
	if len(security.Capabilities.Add) != 0 {
		t.Fatalf("added capabilities = %#v, want none", security.Capabilities.Add)
	}
	if _, ok := container.Resources.Limits[corev1.ResourceEphemeralStorage]; !ok {
		t.Fatal("ephemeral-storage limit is missing")
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].EmptyDir == nil || pod.Volumes[0].EmptyDir.SizeLimit == nil {
		t.Fatal("bounded /tmp emptyDir is missing")
	}

	gotEnv := make(map[string]string)
	gotFieldRefs := make(map[string]string)
	for _, item := range container.Env {
		gotEnv[item.Name] = item.Value
		if item.ValueFrom != nil && item.ValueFrom.FieldRef != nil {
			gotFieldRefs[item.Name] = item.ValueFrom.FieldRef.FieldPath
		}
	}
	for _, name := range []string{
		"PORTSCANNER_EVENT_ID",
		"PORTSCANNER_DIRECTIVE_ID",
		"PORTSCANNER_TRACE_ID",
		"PORTSCANNER_REASON",
		"PORTSCANNER_TARGET_ID",
		"PORTSCANNER_TARGET_PROVIDER",
		"PORTSCANNER_TARGET_SCOPE_ID",
		"PORTSCANNER_TARGET_LOCATION",
		"PORTSCANNER_TARGET_RESOURCE_ID",
		"PORTSCANNER_TARGET_PRIVATE_ADDRESS",
		"PORTSCANNER_TARGET_GENERATION",
		"PORTSCANNER_IMAGE_VERSION",
		"PORTSCANNER_DEADLINE_AT",
		"PORTSCANNER_NOT_AFTER",
		"PORTSCANNER_RESULT_BUCKET",
		"PORTSCANNER_RESULT_PREFIX",
	} {
		if gotEnv[name] == "" {
			t.Fatalf("correlation env %s is empty", name)
		}
	}
	if gotFieldRefs["PORTSCANNER_RUN_ID"] !=
		"metadata.labels['batch.kubernetes.io/job-name']" {
		t.Fatalf("run ID fieldRef = %q", gotFieldRefs["PORTSCANNER_RUN_ID"])
	}
	if gotFieldRefs["PORTSCANNER_ATTEMPT_ID"] != "metadata.uid" {
		t.Fatalf("attempt ID fieldRef = %q", gotFieldRefs["PORTSCANNER_ATTEMPT_ID"])
	}
	if gotEnv["PORTSCANNER_IMAGE_VERSION"] != config.ScannerImage {
		t.Fatal("scanner image version must equal the configured digest-pinned image URI")
	}
	if len(job.Annotations) != 0 || len(job.Spec.Template.Annotations) != 0 {
		t.Fatal("correlation must not rely on annotations")
	}
}

func TestBuildJobAddsDeploymentCIDREnvironmentOnlyWhenConfigured(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)

	jobWithoutCIDRs, err := buildJob(scanner, validJobConfig(), now)
	if err != nil {
		t.Fatalf("buildJob() without CIDRs error = %v", err)
	}
	emptyEnv := make(map[string]string)
	for _, item := range jobWithoutCIDRs.Spec.Template.Spec.Containers[0].Env {
		emptyEnv[item.Name] = item.Value
	}
	for _, name := range []string{"SCANNER_ALLOWED_CIDRS", "SCANNER_DENIED_CIDRS"} {
		if _, ok := emptyEnv[name]; ok {
			t.Fatalf("%s must be omitted when its deployment list is empty", name)
		}
	}

	config := validJobConfig()
	config.AllowedCIDRs = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/28"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
	config.DeniedCIDRs = []netip.Prefix{
		netip.MustParsePrefix("203.0.113.128/25"),
	}
	jobWithCIDRs, err := buildJob(scanner, config, now)
	if err != nil {
		t.Fatalf("buildJob() with CIDRs error = %v", err)
	}
	configuredEnv := make(map[string]string)
	for _, item := range jobWithCIDRs.Spec.Template.Spec.Containers[0].Env {
		configuredEnv[item.Name] = item.Value
	}
	if got := configuredEnv["SCANNER_ALLOWED_CIDRS"]; got != "192.0.2.0/28,198.51.100.0/24" {
		t.Fatalf("SCANNER_ALLOWED_CIDRS = %q", got)
	}
	if got := configuredEnv["SCANNER_DENIED_CIDRS"]; got != "203.0.113.128/25" {
		t.Fatalf("SCANNER_DENIED_CIDRS = %q", got)
	}
}

func TestJobConfigRejectsMutableScannerImage(t *testing.T) {
	config := validJobConfig()
	config.ScannerImage = "example.invalid/portscanner-scanner:latest"
	if err := config.Validate(); err == nil {
		t.Fatal("JobConfig accepted a mutable scanner image tag")
	}
}

func TestJobConfigValidatesCanonicalIPv4Prefixes(t *testing.T) {
	valid := validJobConfig()
	valid.AllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	valid.DeniedCIDRs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if err := valid.Validate(); err != nil {
		t.Fatalf("JobConfig rejected canonical IPv4 prefixes: %v", err)
	}

	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{
			name:   "invalid prefix",
			prefix: netip.Prefix{},
		},
		{
			name:   "IPv6 prefix",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
		},
		{
			name:   "host bits set",
			prefix: netip.MustParsePrefix("192.0.2.1/24"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validJobConfig()
			config.AllowedCIDRs = []netip.Prefix{test.prefix}
			if err := config.Validate(); err == nil {
				t.Fatal("JobConfig accepted an invalid authorization prefix")
			}
		})
	}
}

func TestScannerSpecRejectsUnsafeOrIncompleteTargetIdentity(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name   string
		mutate func(*scanningv1alpha1.ScannerSpec)
	}{
		{
			name: "private public address",
			mutate: func(spec *scanningv1alpha1.ScannerSpec) {
				spec.Target.Address = "10.0.0.20"
			},
		},
		{
			name: "zero generation",
			mutate: func(spec *scanningv1alpha1.ScannerSpec) {
				spec.Target.Generation = 0
			},
		},
		{
			name: "mutable target identifier",
			mutate: func(spec *scanningv1alpha1.ScannerSpec) {
				spec.Target.TargetID = "target-name"
			},
		},
		{
			name: "missing directive identifier",
			mutate: func(spec *scanningv1alpha1.ScannerSpec) {
				spec.DirectiveID = ""
			},
		},
		{
			name: "too many combined coverage terms",
			mutate: func(spec *scanningv1alpha1.ScannerSpec) {
				spec.Ports = make([]int32, maxCoverageTerms/2)
				for index := range spec.Ports {
					spec.Ports[index] = int32(index + 1)
				}
				spec.Ranges = make(
					[]scanningv1alpha1.PortRange,
					maxCoverageTerms-len(spec.Ports)+1,
				)
				for index := range spec.Ranges {
					port := int32(1_000 + index*2)
					spec.Ranges[index] = scanningv1alpha1.PortRange{Start: port, End: port}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validScanner(now).Spec
			test.mutate(&spec)
			if err := validateScannerSpec(spec); err == nil {
				t.Fatal("validateScannerSpec() accepted invalid input")
			}
		})
	}
}

func TestScannerSpecAcceptsTargetChangeReason(t *testing.T) {
	spec := validScanner(time.Now().UTC()).Spec
	spec.Reason = scanningv1alpha1.ReasonTargetChange
	if err := validateScannerSpec(spec); err != nil {
		t.Fatalf("validateScannerSpec() rejected target_change: %v", err)
	}
}

func TestExplicitPortCoverageCapsNormalizedTerms(t *testing.T) {
	spec := validScanner(time.Now().UTC()).Spec
	spec.Profile = scanningv1alpha1.ProfileTargetedTCP
	spec.Ports = make([]int32, maxCoverageTerms+1)
	for index := range spec.Ports {
		spec.Ports[index] = int32(index*2 + 1)
	}
	if _, err := explicitPortCoverage(spec); err == nil {
		t.Fatal("explicitPortCoverage() accepted more than 256 normalized terms")
	}

	for index := range spec.Ports {
		spec.Ports[index] = int32(index + 1)
	}
	got, err := explicitPortCoverage(spec)
	if err != nil {
		t.Fatalf("explicitPortCoverage() rejected one normalized term: %v", err)
	}
	if got != "1-257" {
		t.Fatalf("explicitPortCoverage() = %q, want 1-257", got)
	}
}

func validScanner(now time.Time) *scanningv1alpha1.Scanner {
	return &scanningv1alpha1.Scanner{
		TypeMeta: metav1.TypeMeta{
			APIVersion: scanningv1alpha1.GroupVersion.String(),
			Kind:       "Scanner",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fake-documentation-target",
			Namespace:  "default",
			UID:        types.UID("scanner-uid-1"),
			Generation: 1,
		},
		Spec: scanningv1alpha1.ScannerSpec{
			Target: scanningv1alpha1.ScannerTarget{
				Address:        "192.0.2.10",
				TargetID:       strings.Repeat("1", 64),
				Provider:       "aws",
				ScopeID:        "123456789012",
				Location:       "us-east-1",
				ResourceID:     "eni-0123456789abcdef0",
				PrivateAddress: "10.0.0.10",
				Generation:     7,
			},
			EventID:     strings.Repeat("2", 64),
			DirectiveID: strings.Repeat("3", 64),
			TraceID:     "trace-test-1",
			Reason:      scanningv1alpha1.ReasonNewTarget,
			Profile:     scanningv1alpha1.ProfileFastFullTCP,
			Priority:    500,
			Deadline:    metav1.NewTime(now.Add(5 * time.Minute)),
			NotAfter:    metav1.NewTime(now.Add(10 * time.Minute)),
			SourceTimestamps: scanningv1alpha1.SourceTimestamps{
				EventAt:    metav1.NewTime(now.Add(-time.Minute)),
				ObservedAt: metav1.NewTime(now.Add(-30 * time.Second)),
			},
			RetryLimit:              1,
			TTLSecondsAfterFinished: 600,
		},
	}
}

func validJobConfig() JobConfig {
	return JobConfig{
		ScannerImage:            "registry.example/portscanner-scanner@sha256:" + strings.Repeat("a", 64),
		ScannerImagePullPolicy:  corev1.PullIfNotPresent,
		ServiceAccountName:      "scanner-test",
		ResultBucket:            "results-test",
		ResultPrefix:            "scans/",
		HighPriorityClassName:   "high-scans",
		NormalPriorityClassName: "normal-scans",
		HighPriorityThreshold:   100,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("100m"),
				corev1.ResourceMemory:           resource.MustParse("64Mi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("500m"),
				corev1.ResourceMemory:           resource.MustParse("256Mi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("512Mi"),
			},
		},
		NodeSelector: map[string]string{"scanner": "true"},
		Tolerations: []corev1.Toleration{{
			Key:      "scanner",
			Operator: corev1.TolerationOpEqual,
			Value:    "true",
			Effect:   corev1.TaintEffectNoSchedule,
		}},
		TmpSizeLimit: resource.MustParse("128Mi"),
	}
}
