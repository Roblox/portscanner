// SPDX-FileCopyrightText: 2026 Portscanner contributors
// SPDX-License-Identifier: MIT

package controller

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	fullTCPPortCoverage = "1-65535"
	jobNameHashLength   = 10
	maxContractText     = 256
	maxCoverageTerms    = 256
	targetHashLabel     = "scanning.portscanner.io/target-hash"
)

var (
	immutableScannerImagePattern = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)
	sha256IdentifierPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	safeIdentifierPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$`)
	awsAccountPattern            = regexp.MustCompile(`^[0-9]{12}$`)
	awsRegionPattern             = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	awsNetworkInterfacePattern   = regexp.MustCompile(`^eni-[0-9a-f]{8,32}$`)
	documentationIPv4Prefixes    = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	nonPublicIPv4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 24),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{168, 63, 129, 16}), 32),
	}
)

// JobConfig contains every environment-specific Job setting.
type JobConfig struct {
	ScannerImage            string
	ScannerImagePullPolicy  corev1.PullPolicy
	ScannerNamespace        string
	ServiceAccountName      string
	AllowedCIDRs            []netip.Prefix
	DeniedCIDRs             []netip.Prefix
	MinRate                 int
	MaxRate                 int
	ResultBucket            string
	ResultPrefix            string
	HighPriorityClassName   string
	NormalPriorityClassName string
	HighPriorityThreshold   int32
	Resources               corev1.ResourceRequirements
	NodeSelector            map[string]string
	Tolerations             []corev1.Toleration
	TmpSizeLimit            resource.Quantity
}

// Validate checks that the operator can construct bounded scanner Jobs.
func (c JobConfig) Validate() error {
	if len(c.ScannerImage) > maxContractText || !immutableScannerImagePattern.MatchString(c.ScannerImage) {
		return fmt.Errorf("scanner image must be a digest-pinned OCI image URI")
	}
	if c.ServiceAccountName == "" {
		return fmt.Errorf("scanner service account must be configured")
	}
	if errors := validation.IsDNS1123Label(c.ScannerNamespace); len(errors) > 0 {
		return fmt.Errorf("scanner namespace must be a DNS-1123 label: %s", strings.Join(errors, "; "))
	}
	if err := validateCanonicalIPv4Prefixes("allowed CIDR", c.AllowedCIDRs); err != nil {
		return err
	}
	if err := validateCanonicalIPv4Prefixes("denied CIDR", c.DeniedCIDRs); err != nil {
		return err
	}
	if c.MinRate < 1 || c.MinRate > 2000 {
		return fmt.Errorf("scanner minimum rate must be between 1 and 2000")
	}
	if c.MaxRate < c.MinRate || c.MaxRate > 5000 {
		return fmt.Errorf("scanner maximum rate must be between the minimum rate and 5000")
	}
	if err := validateResultDestination(c.ResultBucket, c.ResultPrefix); err != nil {
		return err
	}
	switch c.ScannerImagePullPolicy {
	case corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
	default:
		return fmt.Errorf("invalid scanner image pull policy %q", c.ScannerImagePullPolicy)
	}
	if c.HighPriorityThreshold < 0 || c.HighPriorityThreshold > 1000 {
		return fmt.Errorf("high priority threshold must be between 0 and 1000")
	}
	if c.HighPriorityClassName == "" || c.NormalPriorityClassName == "" {
		return fmt.Errorf("both priority class names must be configured")
	}
	if c.TmpSizeLimit.IsZero() || c.TmpSizeLimit.Sign() < 0 {
		return fmt.Errorf("tmp size limit must be greater than zero")
	}
	for _, name := range []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourceEphemeralStorage,
	} {
		request, ok := c.Resources.Requests[name]
		if !ok {
			return fmt.Errorf("scanner resource request %q must be configured", name)
		}
		limit, ok := c.Resources.Limits[name]
		if !ok {
			return fmt.Errorf("scanner resource limit %q must be configured", name)
		}
		if request.Sign() <= 0 || limit.Sign() <= 0 {
			return fmt.Errorf("scanner resource %q values must be greater than zero", name)
		}
		if request.Cmp(limit) > 0 {
			return fmt.Errorf("scanner resource request %q exceeds its limit", name)
		}
	}
	return nil
}

func validateResultDestination(bucket string, prefix string) error {
	if len(bucket) < 3 || len(bucket) > 255 {
		return fmt.Errorf("result bucket must contain between 3 and 255 characters")
	}
	for _, character := range bucket {
		if unicode.IsSpace(character) || character < 32 || character == 127 {
			return fmt.Errorf("result bucket contains whitespace or control characters")
		}
	}
	normalizedPrefix := strings.Trim(prefix, "/")
	if normalizedPrefix == "" {
		return fmt.Errorf("result prefix must be a non-empty object-key prefix")
	}
	for _, segment := range strings.Split(normalizedPrefix, "/") {
		if !safeIdentifierPattern.MatchString(segment) {
			return fmt.Errorf("result prefix segment %q is not a bounded safe identifier", segment)
		}
	}
	return nil
}

func deterministicJobName(scanner *scanningv1alpha1.Scanner) string {
	identity := string(scanner.UID)
	if identity == "" {
		identity = scanner.Namespace + "/" + scanner.Name
	}
	sum := sha256.Sum256([]byte(identity))
	suffix := fmt.Sprintf("%x", sum[:])[:jobNameHashLength]

	base := strings.ToLower(scanner.Name)
	var normalized strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			normalized.WriteRune(r)
		} else {
			normalized.WriteByte('-')
		}
	}
	base = strings.Trim(normalized.String(), "-")
	if base == "" {
		base = "scanner"
	}

	const prefix = "scan-"
	maxBase := 63 - len(prefix) - 1 - len(suffix)
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return prefix + base + "-" + suffix
}

func scanDeadlines(spec scanningv1alpha1.ScannerSpec) (time.Time, time.Time, error) {
	if spec.Deadline.IsZero() {
		return time.Time{}, time.Time{}, fmt.Errorf("deadline must be set")
	}
	if spec.NotAfter.IsZero() {
		return time.Time{}, time.Time{}, fmt.Errorf("notAfter must be set")
	}
	deadline := spec.Deadline.Time
	notAfter := spec.NotAfter.Time
	if deadline.After(notAfter) {
		return time.Time{}, time.Time{}, fmt.Errorf("deadline must not be later than notAfter")
	}
	return deadline, notAfter, nil
}

func activeDeadlineSeconds(spec scanningv1alpha1.ScannerSpec, now time.Time) (int64, error) {
	_, notAfter, err := scanDeadlines(spec)
	if err != nil {
		return 0, err
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return 0, fmt.Errorf("scan execution cutoff elapsed at %s", notAfter.UTC().Format(time.RFC3339))
	}
	seconds := int64(remaining / time.Second)
	if seconds < 1 {
		return 0, fmt.Errorf(
			"less than one second remains before scan execution cutoff at %s",
			notAfter.UTC().Format(time.RFC3339),
		)
	}
	return seconds, nil
}

func explicitPortCoverage(spec scanningv1alpha1.ScannerSpec) (string, error) {
	if spec.Profile == scanningv1alpha1.ProfileFastFullTCP {
		return fullTCPPortCoverage, nil
	}

	ports := make([]bool, 65536)
	for _, port := range spec.Ports {
		if port < 1 || port > 65535 {
			return "", fmt.Errorf("port %d is outside 1-65535", port)
		}
		ports[port] = true
	}
	for _, portRange := range spec.Ranges {
		if portRange.Start < 1 || portRange.End > 65535 || portRange.Start > portRange.End {
			return "", fmt.Errorf("invalid port range %d-%d", portRange.Start, portRange.End)
		}
		for port := portRange.Start; port <= portRange.End; port++ {
			ports[port] = true
		}
	}

	var selected []int
	for port := 1; port <= 65535; port++ {
		if ports[port] {
			selected = append(selected, port)
		}
	}
	if len(selected) == 0 {
		if spec.Profile == scanningv1alpha1.ProfileDeep {
			return fullTCPPortCoverage, nil
		}
		return "", fmt.Errorf("%s requires explicit ports or ranges", spec.Profile)
	}

	var parts []string
	for start := 0; start < len(selected); {
		end := start
		for end+1 < len(selected) && selected[end+1] == selected[end]+1 {
			end++
		}
		if start == end {
			parts = append(parts, strconv.Itoa(selected[start]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", selected[start], selected[end]))
		}
		start = end + 1
	}
	if len(parts) > maxCoverageTerms {
		return "", fmt.Errorf(
			"normalized TCP port coverage contains %d terms; maximum is %d",
			len(parts),
			maxCoverageTerms,
		)
	}
	return strings.Join(parts, ","), nil
}

func scannerArguments(spec scanningv1alpha1.ScannerSpec) ([]string, error) {
	coverage, err := explicitPortCoverage(spec)
	if err != nil {
		return nil, err
	}

	args := []string{
		"--target=" + spec.Target.Address,
		"--profile=" + string(spec.Profile),
		"--tcp-ports=" + coverage,
	}
	switch spec.Profile {
	case scanningv1alpha1.ProfileFastFullTCP,
		scanningv1alpha1.ProfileTargetedTCP,
		scanningv1alpha1.ProfileDeep:
	default:
		return nil, fmt.Errorf("unsupported scan profile %q", spec.Profile)
	}
	return args, nil
}

func priorityClassName(priority int32, config JobConfig) string {
	if priority >= config.HighPriorityThreshold {
		return config.HighPriorityClassName
	}
	return config.NormalPriorityClassName
}

func validateScannerSpec(spec scanningv1alpha1.ScannerSpec) error {
	if err := validatePublicIPv4(spec.Target.Address); err != nil {
		return fmt.Errorf("target address: %w", err)
	}
	if !sha256IdentifierPattern.MatchString(spec.Target.TargetID) {
		return fmt.Errorf("targetId must be a lowercase SHA-256 identifier")
	}
	if spec.Target.Provider != "aws" {
		return fmt.Errorf("target provider must be aws")
	}
	if !awsAccountPattern.MatchString(spec.Target.ScopeID) {
		return fmt.Errorf("target scopeId must be a 12-digit AWS account ID")
	}
	if len(spec.Target.Location) < 9 || len(spec.Target.Location) > 32 ||
		!awsRegionPattern.MatchString(spec.Target.Location) {
		return fmt.Errorf("target location must be a bounded AWS region")
	}
	if !awsNetworkInterfacePattern.MatchString(spec.Target.ResourceID) {
		return fmt.Errorf("target resourceId must be an AWS network interface ID")
	}
	if err := validateCanonicalIPv4(spec.Target.PrivateAddress); err != nil {
		return fmt.Errorf("target privateAddress: %w", err)
	}
	if spec.Target.Generation < 1 {
		return fmt.Errorf("target generation must be at least 1")
	}
	if !sha256IdentifierPattern.MatchString(spec.EventID) {
		return fmt.Errorf("eventId must be a lowercase SHA-256 identifier")
	}
	if !sha256IdentifierPattern.MatchString(spec.DirectiveID) {
		return fmt.Errorf("directiveId must be a lowercase SHA-256 identifier")
	}
	if !safeIdentifierPattern.MatchString(spec.TraceID) {
		return fmt.Errorf("traceId must be a bounded safe identifier")
	}
	switch spec.Reason {
	case scanningv1alpha1.ReasonNewTarget,
		scanningv1alpha1.ReasonTargetChange,
		scanningv1alpha1.ReasonPolicyChange,
		scanningv1alpha1.ReasonCoverage,
		scanningv1alpha1.ReasonManual:
	default:
		return fmt.Errorf("unsupported scan reason %q", spec.Reason)
	}
	if spec.Priority < 0 || spec.Priority > 1000 {
		return fmt.Errorf("priority must be between 0 and 1000")
	}
	if len(spec.Ports)+len(spec.Ranges) > maxCoverageTerms {
		return fmt.Errorf(
			"combined TCP port and range coverage contains %d terms; maximum is %d",
			len(spec.Ports)+len(spec.Ranges),
			maxCoverageTerms,
		)
	}
	if spec.RetryLimit < 0 || spec.RetryLimit > 6 {
		return fmt.Errorf("retryLimit must be between 0 and 6")
	}
	if spec.TTLSecondsAfterFinished < 0 {
		return fmt.Errorf("ttlSecondsAfterFinished must not be negative")
	}
	if spec.SourceTimestamps.EventAt.IsZero() || spec.SourceTimestamps.ObservedAt.IsZero() {
		return fmt.Errorf("source eventAt and observedAt timestamps must be set")
	}
	if spec.SourceTimestamps.EventAt.After(spec.SourceTimestamps.ObservedAt.Time) {
		return fmt.Errorf("source eventAt must not be later than observedAt")
	}
	_, _, err := scanDeadlines(spec)
	return err
}

func validateCanonicalIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return fmt.Errorf("must be a canonical IPv4 literal")
	}
	return nil
}

func validateCanonicalIPv4Prefixes(name string, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return fmt.Errorf("%s %q must be a canonical IPv4 prefix", name, prefix)
		}
	}
	return nil
}

func validatePublicIPv4(value string) error {
	if err := validateCanonicalIPv4(value); err != nil {
		return err
	}
	address := netip.MustParseAddr(value)
	for _, prefix := range documentationIPv4Prefixes {
		if prefix.Contains(address) {
			return nil
		}
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("must be a public IPv4 literal")
		}
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return fmt.Errorf("must be a public IPv4 literal")
	}
	return nil
}

func buildJob(scanner *scanningv1alpha1.Scanner, config JobConfig, now time.Time) (*batchv1.Job, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateScannerSpec(scanner.Spec); err != nil {
		return nil, err
	}
	if scanner.Namespace != config.ScannerNamespace {
		return nil, fmt.Errorf(
			"Scanner namespace %q is outside configured namespace %q",
			scanner.Namespace,
			config.ScannerNamespace,
		)
	}
	args, err := scannerArguments(scanner.Spec)
	if err != nil {
		return nil, err
	}
	args = append(
		args,
		fmt.Sprintf("--min-rate=%d", config.MinRate),
		fmt.Sprintf("--max-rate=%d", config.MaxRate),
	)
	deadlineSeconds, err := activeDeadlineSeconds(scanner.Spec, now)
	if err != nil {
		return nil, err
	}

	retryLimit := scanner.Spec.RetryLimit
	ttlSeconds := scanner.Spec.TTLSecondsAfterFinished
	parallelism := int32(1)
	completions := int32(1)
	controller := true
	blockOwnerDeletion := true
	runAsNonRoot := true
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	enableServiceLinks := false
	terminationGracePeriodSeconds := int64(30)
	tmpSize := config.TmpSizeLimit.DeepCopy()
	jobName := deterministicJobName(scanner)

	env := []corev1.EnvVar{
		{Name: "PORTSCANNER_EVENT_ID", Value: scanner.Spec.EventID},
		{Name: "PORTSCANNER_DIRECTIVE_ID", Value: scanner.Spec.DirectiveID},
		{Name: "PORTSCANNER_TRACE_ID", Value: scanner.Spec.TraceID},
		{Name: "PORTSCANNER_REASON", Value: string(scanner.Spec.Reason)},
		{Name: "PORTSCANNER_TARGET_ID", Value: scanner.Spec.Target.TargetID},
		{Name: "PORTSCANNER_TARGET_PROVIDER", Value: scanner.Spec.Target.Provider},
		{Name: "PORTSCANNER_TARGET_SCOPE_ID", Value: scanner.Spec.Target.ScopeID},
		{Name: "PORTSCANNER_TARGET_LOCATION", Value: scanner.Spec.Target.Location},
		{Name: "PORTSCANNER_TARGET_RESOURCE_ID", Value: scanner.Spec.Target.ResourceID},
		{Name: "PORTSCANNER_TARGET_PRIVATE_ADDRESS", Value: scanner.Spec.Target.PrivateAddress},
		{Name: "PORTSCANNER_TARGET_GENERATION", Value: strconv.FormatInt(scanner.Spec.Target.Generation, 10)},
		{
			Name: "PORTSCANNER_RUN_ID",
			ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.labels['batch.kubernetes.io/job-name']",
			}},
		},
		{
			Name: "PORTSCANNER_ATTEMPT_ID",
			ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.uid",
			}},
		},
		{Name: "PORTSCANNER_IMAGE_VERSION", Value: config.ScannerImage},
		{Name: "PORTSCANNER_SOURCE_EVENT_AT", Value: scanner.Spec.SourceTimestamps.EventAt.UTC().Format(time.RFC3339Nano)},
		{Name: "PORTSCANNER_SOURCE_OBSERVED_AT", Value: scanner.Spec.SourceTimestamps.ObservedAt.UTC().Format(time.RFC3339Nano)},
		{Name: "PORTSCANNER_DEADLINE_AT", Value: scanner.Spec.Deadline.UTC().Format(time.RFC3339Nano)},
		{Name: "PORTSCANNER_NOT_AFTER", Value: scanner.Spec.NotAfter.UTC().Format(time.RFC3339Nano)},
		{Name: "PORTSCANNER_RESULT_BUCKET", Value: config.ResultBucket},
		{Name: "PORTSCANNER_RESULT_PREFIX", Value: config.ResultPrefix},
		{Name: "PORTSCANNER_RESOURCE_NAME", Value: scanner.Name},
		{Name: "PORTSCANNER_RESOURCE_NAMESPACE", Value: scanner.Namespace},
	}
	if len(config.DeniedCIDRs) > 0 {
		env = append(env, corev1.EnvVar{
			Name:  "SCANNER_DENIED_CIDRS",
			Value: joinPrefixes(config.DeniedCIDRs),
		})
	}
	if len(config.AllowedCIDRs) > 0 {
		env = append(env, corev1.EnvVar{
			Name:  "SCANNER_ALLOWED_CIDRS",
			Value: joinPrefixes(config.AllowedCIDRs),
		})
	}

	labels := map[string]string{
		"app.kubernetes.io/name":       "portscanner",
		"app.kubernetes.io/component":  "scanner",
		"scanning.portscanner.io/name": scannerLabelValue(scanner.Name),
		"batch.kubernetes.io/job-name": jobName,
		targetHashLabel:                targetAddressHash(scanner.Spec.Target.Address),
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:       jobName,
			Namespace:  scanner.Namespace,
			Labels:     labels,
			Finalizers: []string{jobFinalizer},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         scanningv1alpha1.GroupVersion.String(),
				Kind:               "Scanner",
				Name:               scanner.Name,
				UID:                scanner.UID,
				Controller:         &controller,
				BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: batchv1.JobSpec{
			Parallelism:             &parallelism,
			Completions:             &completions,
			BackoffLimit:            &retryLimit,
			TTLSecondsAfterFinished: &ttlSeconds,
			ActiveDeadlineSeconds:   &deadlineSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: copyStringMap(labels)},
				Spec: corev1.PodSpec{
					ServiceAccountName:           config.ServiceAccountName,
					AutomountServiceAccountToken: boolPointer(false),
					RestartPolicy:                corev1.RestartPolicyNever,
					PriorityClassName:            priorityClassName(scanner.Spec.Priority, config),
					NodeSelector:                 copyStringMap(config.NodeSelector),
					Tolerations:                  append([]corev1.Toleration(nil), config.Tolerations...),
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
								LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
									"app.kubernetes.io/component": "scanner",
								}},
								MatchLabelKeys:    []string{targetHashLabel},
								NamespaceSelector: &metav1.LabelSelector{},
								TopologyKey:       corev1.LabelTopologyRegion,
							}},
						},
					},
					EnableServiceLinks:            &enableServiceLinks,
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &runAsNonRoot,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            "scanner",
						Image:           config.ScannerImage,
						ImagePullPolicy: config.ScannerImagePullPolicy,
						Args:            args,
						Env:             env,
						Resources:       *config.Resources.DeepCopy(),
						SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot:             &runAsNonRoot,
							AllowPrivilegeEscalation: &allowPrivilegeEscalation,
							ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "tmp",
							MountPath: "/tmp",
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tmpSize},
						},
					}},
				},
			},
		},
	}, nil
}

func boolPointer(value bool) *bool {
	return &value
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func joinPrefixes(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = prefix.String()
	}
	return strings.Join(values, ",")
}

func scannerLabelValue(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	suffix := fmt.Sprintf("%x", sum[:])[:8]
	base := strings.TrimRight(name[:54], "-.")
	if base == "" {
		base = "scanner"
	}
	return base + "-" + suffix
}

func targetAddressHash(address string) string {
	sum := sha256.Sum256([]byte(address))
	return fmt.Sprintf("%x", sum[:])[:32]
}
