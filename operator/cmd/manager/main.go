// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
	scannercontroller "github.com/Roblox/portscanner/operator/internal/controller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
	utilruntime.Must(scanningv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddress         string
		healthAddress          string
		leaderElection         bool
		leaderElectionID       string
		maxConcurrent          int
		scannerImage           string
		scannerImagePullPolicy string
		scannerServiceAccount  string
		scannerNamespace       string
		allowedCIDRsJSON       string
		deniedCIDRsJSON        string
		scannerMinRate         int
		scannerMaxRate         int
		resultBucket           string
		resultPrefix           string
		highPriorityClass      string
		normalPriorityClass    string
		highPriorityThreshold  int
		cpuRequest             string
		cpuLimit               string
		memoryRequest          string
		memoryLimit            string
		ephemeralRequest       string
		ephemeralLimit         string
		tmpSizeLimit           string
		nodeSelectorValue      string
		tolerationsJSON        string
	)

	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "Address for the metrics endpoint; use 0 to disable.")
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "Address for health probes.")
	flag.BoolVar(&leaderElection, "leader-elect", true, "Enable leader election.")
	flag.StringVar(&leaderElectionID, "leader-election-id", "portscanner-operator.scanning.portscanner.io", "Leader election lease name.")
	flag.IntVar(&maxConcurrent, "max-concurrent-reconciles", 4, "Maximum concurrent Scanner reconciliations.")
	flag.StringVar(&scannerImage, "scanner-image", "", "Scanner container image, including an immutable tag or digest.")
	flag.StringVar(&scannerImagePullPolicy, "scanner-image-pull-policy", string(corev1.PullIfNotPresent), "Scanner image pull policy.")
	flag.StringVar(&scannerServiceAccount, "scanner-service-account", "portscanner-scanner", "ServiceAccount used by scanner Jobs.")
	flag.StringVar(&scannerNamespace, "scanner-namespace", "portscanner", "Single namespace watched for Scanner resources and Jobs.")
	flag.StringVar(&allowedCIDRsJSON, "scanner-allowed-cidrs-json", "[]", "JSON array of deployment-authorized canonical IPv4 CIDRs.")
	flag.StringVar(&deniedCIDRsJSON, "scanner-denied-cidrs-json", "[]", "JSON array of deployment-denied canonical IPv4 CIDRs.")
	flag.IntVar(&scannerMinRate, "scanner-min-rate", 100, "Minimum Nmap probe rate for scanner Jobs.")
	flag.IntVar(&scannerMaxRate, "scanner-max-rate", 500, "Maximum Nmap probe rate for scanner Jobs.")
	flag.StringVar(&resultBucket, "result-bucket", "", "Result object-store bucket name.")
	flag.StringVar(&resultPrefix, "result-prefix", "", "Result object key prefix.")
	flag.StringVar(&highPriorityClass, "high-priority-class", "portscanner-high", "PriorityClass for high-priority requests.")
	flag.StringVar(&normalPriorityClass, "normal-priority-class", "portscanner-normal", "PriorityClass for normal-priority requests.")
	flag.IntVar(&highPriorityThreshold, "high-priority-threshold", 100, "Priority value at or above which the high class is used.")
	flag.StringVar(&cpuRequest, "scanner-cpu-request", "100m", "Scanner CPU request.")
	flag.StringVar(&cpuLimit, "scanner-cpu-limit", "1", "Scanner CPU limit.")
	flag.StringVar(&memoryRequest, "scanner-memory-request", "128Mi", "Scanner memory request.")
	flag.StringVar(&memoryLimit, "scanner-memory-limit", "512Mi", "Scanner memory limit.")
	flag.StringVar(&ephemeralRequest, "scanner-ephemeral-storage-request", "128Mi", "Scanner ephemeral-storage request.")
	flag.StringVar(&ephemeralLimit, "scanner-ephemeral-storage-limit", "1Gi", "Scanner ephemeral-storage limit.")
	flag.StringVar(&tmpSizeLimit, "scanner-tmp-size-limit", "256Mi", "Size limit for the scanner /tmp emptyDir.")
	flag.StringVar(&nodeSelectorValue, "scanner-node-selector", "", "Comma-separated key=value node selector.")
	flag.StringVar(&tolerationsJSON, "scanner-tolerations-json", "[]", "JSON array of Kubernetes tolerations.")

	zapOptions := zap.Options{Development: false}
	zapOptions.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOptions)))

	if maxConcurrent < 1 {
		exitWithError(fmt.Errorf("max-concurrent-reconciles must be at least 1"))
	}
	if highPriorityThreshold < 0 || highPriorityThreshold > 1000 {
		exitWithError(fmt.Errorf("high-priority-threshold must be between 0 and 1000"))
	}

	nodeSelector, err := parseNodeSelector(nodeSelectorValue)
	if err != nil {
		exitWithError(err)
	}
	var tolerations []corev1.Toleration
	if err := json.Unmarshal([]byte(tolerationsJSON), &tolerations); err != nil {
		exitWithError(fmt.Errorf("parse scanner-tolerations-json: %w", err))
	}
	allowedCIDRs, err := parseCanonicalIPv4PrefixesJSON("scanner-allowed-cidrs-json", allowedCIDRsJSON)
	if err != nil {
		exitWithError(err)
	}
	deniedCIDRs, err := parseCanonicalIPv4PrefixesJSON("scanner-denied-cidrs-json", deniedCIDRsJSON)
	if err != nil {
		exitWithError(err)
	}

	resources, err := scannerResources(
		cpuRequest,
		cpuLimit,
		memoryRequest,
		memoryLimit,
		ephemeralRequest,
		ephemeralLimit,
	)
	if err != nil {
		exitWithError(err)
	}
	tmpQuantity, err := resource.ParseQuantity(tmpSizeLimit)
	if err != nil {
		exitWithError(fmt.Errorf("parse scanner-tmp-size-limit: %w", err))
	}

	jobConfig := scannercontroller.JobConfig{
		ScannerImage:            scannerImage,
		ScannerImagePullPolicy:  corev1.PullPolicy(scannerImagePullPolicy),
		ScannerNamespace:        scannerNamespace,
		ServiceAccountName:      scannerServiceAccount,
		AllowedCIDRs:            allowedCIDRs,
		DeniedCIDRs:             deniedCIDRs,
		MinRate:                 scannerMinRate,
		MaxRate:                 scannerMaxRate,
		ResultBucket:            resultBucket,
		ResultPrefix:            resultPrefix,
		HighPriorityClassName:   highPriorityClass,
		NormalPriorityClassName: normalPriorityClass,
		HighPriorityThreshold:   int32(highPriorityThreshold),
		Resources:               resources,
		NodeSelector:            nodeSelector,
		Tolerations:             tolerations,
		TmpSizeLimit:            tmpQuantity,
	}
	if err := validatePullPolicy(jobConfig.ScannerImagePullPolicy); err != nil {
		exitWithError(err)
	}
	if err := jobConfig.Validate(); err != nil {
		exitWithError(err)
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			scannerNamespace: {},
		}},
		Metrics:                 metricsserver.Options{BindAddress: metricsAddress},
		HealthProbeBindAddress:  healthAddress,
		LeaderElection:          leaderElection,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: scannerNamespace,
	})
	if err != nil {
		exitWithError(fmt.Errorf("create manager: %w", err))
	}

	reconciler := &scannercontroller.ScannerReconciler{
		Client:    manager.GetClient(),
		Scheme:    manager.GetScheme(),
		JobConfig: jobConfig,
	}
	if err := reconciler.SetupWithManager(manager, maxConcurrent); err != nil {
		exitWithError(fmt.Errorf("set up Scanner controller: %w", err))
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		exitWithError(fmt.Errorf("set up health check: %w", err))
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		exitWithError(fmt.Errorf("set up readiness check: %w", err))
	}

	setupLog.Info("starting manager")
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		exitWithError(fmt.Errorf("run manager: %w", err))
	}
}

func parseCanonicalIPv4PrefixesJSON(flagName string, value string) ([]netip.Prefix, error) {
	var rawCIDRs []string
	if err := json.Unmarshal([]byte(value), &rawCIDRs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", flagName, err)
	}
	if rawCIDRs == nil {
		return nil, fmt.Errorf("%s must be a JSON array", flagName)
	}

	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, rawCIDR := range rawCIDRs {
		prefix, err := netip.ParsePrefix(rawCIDR)
		if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() ||
			prefix != prefix.Masked() || prefix.String() != rawCIDR {
			return nil, fmt.Errorf("%s item %q must be a canonical IPv4 prefix", flagName, rawCIDR)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseNodeSelector(value string) (map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	result := make(map[string]string)
	for _, item := range strings.Split(value, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid scanner-node-selector item %q; expected key=value", item)
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func scannerResources(
	cpuRequest string,
	cpuLimit string,
	memoryRequest string,
	memoryLimit string,
	ephemeralRequest string,
	ephemeralLimit string,
) (corev1.ResourceRequirements, error) {
	values := map[string]string{
		"scanner-cpu-request":               cpuRequest,
		"scanner-cpu-limit":                 cpuLimit,
		"scanner-memory-request":            memoryRequest,
		"scanner-memory-limit":              memoryLimit,
		"scanner-ephemeral-storage-request": ephemeralRequest,
		"scanner-ephemeral-storage-limit":   ephemeralLimit,
	}
	parsed := make(map[string]resource.Quantity, len(values))
	for name, value := range values {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return corev1.ResourceRequirements{}, fmt.Errorf("parse %s: %w", name, err)
		}
		parsed[name] = quantity
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:              parsed["scanner-cpu-request"],
			corev1.ResourceMemory:           parsed["scanner-memory-request"],
			corev1.ResourceEphemeralStorage: parsed["scanner-ephemeral-storage-request"],
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:              parsed["scanner-cpu-limit"],
			corev1.ResourceMemory:           parsed["scanner-memory-limit"],
			corev1.ResourceEphemeralStorage: parsed["scanner-ephemeral-storage-limit"],
		},
	}, nil
}

func validatePullPolicy(policy corev1.PullPolicy) error {
	switch policy {
	case corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
		return nil
	default:
		return fmt.Errorf("invalid scanner-image-pull-policy %q", policy)
	}
}

func exitWithError(err error) {
	setupLog.Error(err, "fatal setup error")
	os.Exit(1)
}
