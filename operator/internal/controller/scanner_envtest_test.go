// SPDX-FileCopyrightText: 2026 Portscanner contributors
// SPDX-License-Identifier: MIT

//go:build envtest

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestEnvtestOneShotCreation uses a local envtest API server. It is excluded
// from normal unit tests and never uses the caller's live kubeconfig.
func TestEnvtestOneShotCreation(t *testing.T) {
	testEnvironment := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../config/crd/bases"},
		ErrorIfCRDPathMissing: true,
	}
	restConfig, err := testEnvironment.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnvironment.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	scheme := runtime.NewScheme()
	for name, add := range map[string]func(*runtime.Scheme) error{
		"client-go": clientgoscheme.AddToScheme,
		"batch":     batchv1.AddToScheme,
		"Scanner":   scanningv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("add %s scheme: %v", name, err)
		}
	}

	manager, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	jobConfig := validJobConfig()
	jobConfig.ScannerNamespace = "scanner-envtest"
	reconciler := &ScannerReconciler{
		Client:    manager.GetClient(),
		Scheme:    scheme,
		JobConfig: jobConfig,
	}
	if err := reconciler.SetupWithManager(manager, 1); err != nil {
		t.Fatalf("set up controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	managerErrors := make(chan error, 1)
	go func() {
		managerErrors <- manager.Start(ctx)
	}()
	if !manager.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("manager cache did not synchronize")
	}

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: jobConfig.ScannerNamespace}}
	if err := manager.GetClient().Create(ctx, namespace); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	now := time.Now().UTC()
	scanner := validScanner(now)
	scanner.Namespace = namespace.Name
	scanner.UID = ""
	scanner.ResourceVersion = ""
	scanner.Generation = 0
	scanner.Spec.Reason = scanningv1alpha1.ReasonTargetChange
	if err := manager.GetClient().Create(ctx, scanner); err != nil {
		t.Fatalf("create Scanner: %v", err)
	}

	if err := eventually(15*time.Second, 100*time.Millisecond, func() (bool, error) {
		var jobs batchv1.JobList
		if err := manager.GetClient().List(ctx, &jobs, client.InNamespace(namespace.Name)); err != nil {
			return false, err
		}
		return len(jobs.Items) == 1, nil
	}); err != nil {
		t.Fatal(err)
	}

	// Allow owned-Job and status events to enqueue duplicate reconciliations.
	time.Sleep(300 * time.Millisecond)
	var jobs batchv1.JobList
	if err := manager.GetClient().List(ctx, &jobs, client.InNamespace(namespace.Name)); err != nil {
		t.Fatalf("list Jobs: %v", err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("Jobs after duplicate events = %d, want 1", len(jobs.Items))
	}
	if jobs.Items[0].Name != deterministicJobName(scanner) {
		t.Fatalf("Job name = %q, want deterministic %q", jobs.Items[0].Name, deterministicJobName(scanner))
	}

	tooManyTerms := validScanner(now)
	tooManyTerms.Name = "too-many-coverage-terms"
	tooManyTerms.Namespace = namespace.Name
	tooManyTerms.UID = ""
	tooManyTerms.ResourceVersion = ""
	tooManyTerms.Generation = 0
	tooManyTerms.Spec.Profile = scanningv1alpha1.ProfileTargetedTCP
	tooManyTerms.Spec.Ports = make([]int32, maxCoverageTerms/2)
	for index := range tooManyTerms.Spec.Ports {
		tooManyTerms.Spec.Ports[index] = int32(index + 1)
	}
	tooManyTerms.Spec.Ranges = make(
		[]scanningv1alpha1.PortRange,
		maxCoverageTerms-len(tooManyTerms.Spec.Ports)+1,
	)
	for index := range tooManyTerms.Spec.Ranges {
		port := int32(1_000 + index*2)
		tooManyTerms.Spec.Ranges[index] = scanningv1alpha1.PortRange{Start: port, End: port}
	}
	if err := manager.GetClient().Create(ctx, tooManyTerms); !apierrors.IsInvalid(err) {
		t.Fatalf("oversized coverage create error = %v, want Invalid", err)
	}

	var stored scanningv1alpha1.Scanner
	if err := manager.GetClient().Get(ctx, client.ObjectKeyFromObject(scanner), &stored); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	stored.Spec.Reason = "mutated-execution"
	if err := manager.GetClient().Update(ctx, &stored); !apierrors.IsInvalid(err) {
		t.Fatalf("immutable execution update error = %v, want Invalid", err)
	}

	if err := manager.GetClient().Get(ctx, client.ObjectKeyFromObject(scanner), &stored); err != nil {
		t.Fatalf("refresh Scanner: %v", err)
	}
	stored.Spec.Cancel = true
	if err := manager.GetClient().Update(ctx, &stored); err != nil {
		t.Fatalf("set cancel: %v", err)
	}
	if err := eventually(15*time.Second, 100*time.Millisecond, func() (bool, error) {
		if err := manager.GetClient().Get(ctx, client.ObjectKeyFromObject(scanner), &stored); err != nil {
			return false, err
		}
		return stored.Status.Outcome == scanningv1alpha1.OutcomeCancelled, nil
	}); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-managerErrors:
		if err != nil {
			t.Fatalf("manager stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not stop")
	}
}

func eventually(timeout, interval time.Duration, check func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := check()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		time.Sleep(interval)
	}
	return fmt.Errorf("condition was not met within %s", timeout)
}
