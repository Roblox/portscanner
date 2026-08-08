// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"
	"time"

	scanningv1alpha1 "github.com/Roblox/portscanner/operator/api/v1alpha1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReconcileCreatesOneDeterministicJob(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}

	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var jobs batchv1.JobList
	if err := fakeClient.List(context.Background(), &jobs, client.InNamespace(scanner.Namespace)); err != nil {
		t.Fatalf("list Jobs: %v", err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("Jobs created = %d, want 1", len(jobs.Items))
	}
	if jobs.Items[0].Name != deterministicJobName(scanner) {
		t.Fatalf("Job name = %q, want %q", jobs.Items[0].Name, deterministicJobName(scanner))
	}
	if !metav1.IsControlledBy(&jobs.Items[0], scanner) {
		t.Fatal("Job is not controlled by Scanner")
	}

	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	if updated.Status.Outcome != scanningv1alpha1.OutcomePending {
		t.Fatalf("outcome = %q, want Pending", updated.Status.Outcome)
	}
	if updated.Status.ActiveJobRef == nil || updated.Status.ActiveJobRef.Name != jobs.Items[0].Name {
		t.Fatal("active Job reference was not recorded")
	}
}

func TestReconcileRejectsExpiredBeforeCreation(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	scanner.Spec.Deadline = metav1.NewTime(now.Add(-2 * time.Second))
	scanner.Spec.NotAfter = metav1.NewTime(now.Add(-time.Second))
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}

	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var jobs batchv1.JobList
	if err := fakeClient.List(context.Background(), &jobs, client.InNamespace(scanner.Namespace)); err != nil {
		t.Fatalf("list Jobs: %v", err)
	}
	if len(jobs.Items) != 0 {
		t.Fatalf("Jobs created = %d, want 0", len(jobs.Items))
	}
	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	if updated.Status.Outcome != scanningv1alpha1.OutcomeExpired {
		t.Fatalf("outcome = %q, want Expired", updated.Status.Outcome)
	}
}

func TestReconcileCreatesJobAfterProducerDispatchDeadline(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	scanner.Spec.Deadline = metav1.NewTime(now.Add(-time.Minute))
	scanner.Spec.NotAfter = metav1.NewTime(now.Add(10 * time.Minute))
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get Job after dispatch deadline: %v", err)
	}
	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner after dispatch deadline: %v", err)
	}
	if isTerminal(updated.Status.Outcome) {
		t.Fatalf("Scanner became terminal at producer dispatch deadline: %q", updated.Status.Outcome)
	}
}

func TestReconcileReportsJobFailure(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get Job: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{
		Type:               batchv1.JobFailed,
		Status:             corev1.ConditionTrue,
		Reason:             "BackoffLimitExceeded",
		LastTransitionTime: metav1.NewTime(now.Add(time.Minute)),
	}}
	if err := fakeClient.Status().Update(context.Background(), &job); err != nil {
		t.Fatalf("update Job status: %v", err)
	}

	reconcile(t, reconciler, request)

	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	if updated.Status.Outcome != scanningv1alpha1.OutcomeFailed {
		t.Fatalf("outcome = %q, want Failed", updated.Status.Outcome)
	}
	if updated.Status.ActiveJobRef != nil {
		t.Fatal("terminal Scanner retained an active Job reference")
	}
	if updated.Status.CompletedAt == nil {
		t.Fatal("terminal Scanner has no completion timestamp")
	}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get completed Job: %v", err)
	}
	if containsString(job.Finalizers, jobFinalizer) {
		t.Fatal("status-protection finalizer was not released")
	}
}

func TestReconcileReportsJobSuccess(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get Job: %v", err)
	}
	completedAt := metav1.NewTime(now.Add(time.Minute))
	job.Status.Conditions = []batchv1.JobCondition{{
		Type:               batchv1.JobComplete,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: completedAt,
	}}
	if err := fakeClient.Status().Update(context.Background(), &job); err != nil {
		t.Fatalf("update Job status: %v", err)
	}

	reconcile(t, reconciler, request)

	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	if updated.Status.Outcome != scanningv1alpha1.OutcomeSucceeded {
		t.Fatalf("outcome = %q, want Succeeded", updated.Status.Outcome)
	}
	condition := meta.FindStatusCondition(updated.Status.Conditions, scanningv1alpha1.ConditionComplete)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatal("successful Scanner has no true Complete condition")
	}
}

func TestTerminalScannerRequeuesUntilTTLThenDeletes(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	scanner.Spec.TTLSecondsAfterFinished = 60
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get Job: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{
		Type:               batchv1.JobComplete,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(now.Add(-30 * time.Second)),
	}}
	if err := fakeClient.Status().Update(context.Background(), &job); err != nil {
		t.Fatalf("update Job status: %v", err)
	}

	result := reconcileResult(t, reconciler, request)
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("terminal requeueAfter = %s, want 30s", result.RequeueAfter)
	}
	var stored scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &stored); err != nil {
		t.Fatalf("Scanner was deleted before TTL: %v", err)
	}

	reconciler.Clock = func() time.Time { return now.Add(31 * time.Second) }
	result = reconcileResult(t, reconciler, request)
	if !result.Requeue {
		t.Fatal("expired terminal Scanner deletion did not request finalizer reconciliation")
	}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal Scanner get error = %v, want NotFound", err)
	}
}

func TestCoverageScannerWithZeroTTLIsEventuallyRemoved(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	scanner.Spec.Reason = scanningv1alpha1.ReasonCoverage
	scanner.Spec.TTLSecondsAfterFinished = 0
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); err != nil {
		t.Fatalf("get Job: %v", err)
	}
	job.Status.Conditions = []batchv1.JobCondition{{
		Type:               batchv1.JobComplete,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(now),
	}}
	if err := fakeClient.Status().Update(context.Background(), &job); err != nil {
		t.Fatalf("update Job status: %v", err)
	}

	if result := reconcileResult(t, reconciler, request); !result.Requeue {
		t.Fatal("zero-TTL terminal Scanner was not queued for immediate deletion")
	}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var stored scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
		t.Fatalf("coverage Scanner get error = %v, want NotFound", err)
	}
	if err := fakeClient.Get(context.Background(), jobKey, &job); !apierrors.IsNotFound(err) {
		t.Fatalf("owned coverage Job get error = %v, want NotFound", err)
	}
}

func TestReconcileCancellationDeletesJob(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var updated scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	updated.Spec.Cancel = true
	if err := fakeClient.Update(context.Background(), &updated); err != nil {
		t.Fatalf("request cancellation: %v", err)
	}

	reconcile(t, reconciler, request)

	if err := fakeClient.Get(context.Background(), request.NamespacedName, &updated); err != nil {
		t.Fatalf("get cancelled Scanner: %v", err)
	}
	if updated.Status.Outcome != scanningv1alpha1.OutcomeCancelled {
		t.Fatalf("outcome = %q, want Cancelled", updated.Status.Outcome)
	}
	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); !apierrors.IsNotFound(err) {
		t.Fatalf("cancelled Job get error = %v, want NotFound", err)
	}
}

func TestReconcileDeletionFinalizesOwnedJob(t *testing.T) {
	now := time.Date(2026, time.August, 5, 20, 0, 0, 0, time.UTC)
	scanner := validScanner(now)
	reconciler, fakeClient := newTestReconciler(t, now, scanner)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(scanner)}
	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	var stored scanningv1alpha1.Scanner
	if err := fakeClient.Get(context.Background(), request.NamespacedName, &stored); err != nil {
		t.Fatalf("get Scanner: %v", err)
	}
	if err := fakeClient.Delete(context.Background(), &stored); err != nil {
		t.Fatalf("delete Scanner: %v", err)
	}

	reconcile(t, reconciler, request)
	reconcile(t, reconciler, request)

	if err := fakeClient.Get(context.Background(), request.NamespacedName, &stored); !apierrors.IsNotFound(err) {
		t.Fatalf("deleted Scanner get error = %v, want NotFound", err)
	}
	var job batchv1.Job
	jobKey := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := fakeClient.Get(context.Background(), jobKey, &job); !apierrors.IsNotFound(err) {
		t.Fatalf("owned Job get error = %v, want NotFound", err)
	}
}

func newTestReconciler(
	t *testing.T,
	now time.Time,
	objects ...client.Object,
) (*ScannerReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add batch scheme: %v", err)
	}
	if err := scanningv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add Scanner scheme: %v", err)
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&scanningv1alpha1.Scanner{}, &batchv1.Job{}).
		WithObjects(objects...).
		Build()
	reconciler := &ScannerReconciler{
		Client:    fakeClient,
		Scheme:    scheme,
		JobConfig: validJobConfig(),
		Clock:     func() time.Time { return now },
	}
	return reconciler, fakeClient
}

func reconcile(t *testing.T, reconciler *ScannerReconciler, request ctrl.Request) {
	t.Helper()
	_ = reconcileResult(t, reconciler, request)
}

func reconcileResult(t *testing.T, reconciler *ScannerReconciler, request ctrl.Request) ctrl.Result {
	t.Helper()
	result, err := reconciler.Reconcile(context.Background(), request)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	return result
}
