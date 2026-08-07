// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"reflect"
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
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const (
	scannerFinalizer = "scanning.portscanner.io/scanner-finalizer"
	jobFinalizer     = "scanning.portscanner.io/status-protection"
)

// ScannerReconciler reconciles Scanner resources into deterministic one-shot
// Jobs.
type ScannerReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	JobConfig JobConfig
	Clock     func() time.Time
}

// +kubebuilder:rbac:groups=scanning.portscanner.io,resources=scanners,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=scanning.portscanner.io,resources=scanners/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=scanning.portscanner.io,resources=scanners/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=jobs/status,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile creates no more than one deterministic Job for each Scanner and
// mirrors only lifecycle state into Scanner status.
func (r *ScannerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var scanner scanningv1alpha1.Scanner
	if err := r.Get(ctx, req.NamespacedName, &scanner); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	now := time.Now().UTC()
	if r.Clock != nil {
		now = r.Clock().UTC()
	}

	if !scanner.DeletionTimestamp.IsZero() {
		return r.reconcileDeletion(ctx, &scanner)
	}

	if !containsString(scanner.Finalizers, scannerFinalizer) {
		before := scanner.DeepCopy()
		scanner.Finalizers = append(scanner.Finalizers, scannerFinalizer)
		if err := r.Patch(ctx, &scanner, client.MergeFrom(before)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if isTerminal(scanner.Status.Outcome) {
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	if scanner.Spec.Cancel {
		if err := r.requestJobDeletion(ctx, &scanner); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchStatus(ctx, &scanner, func() {
			setTerminalStatus(&scanner, scanningv1alpha1.OutcomeCancelled, "Cancelled", "scan cancelled before completion", now)
			meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
				Type:               scanningv1alpha1.ConditionAccepted,
				Status:             metav1.ConditionFalse,
				Reason:             "Cancelled",
				Message:            "scan cancellation was requested",
				ObservedGeneration: scanner.Generation,
			})
		}); err != nil {
			return ctrl.Result{}, err
		}
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	_, notAfter, err := scanDeadlines(scanner.Spec)
	if err != nil {
		if statusErr := r.patchStatus(ctx, &scanner, func() {
			setTerminalStatus(&scanner, scanningv1alpha1.OutcomeFailed, "InvalidRequest", err.Error(), now)
			meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
				Type:               scanningv1alpha1.ConditionAccepted,
				Status:             metav1.ConditionFalse,
				Reason:             "InvalidRequest",
				Message:            err.Error(),
				ObservedGeneration: scanner.Generation,
			})
		}); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	jobKey := types.NamespacedName{Name: deterministicJobName(&scanner), Namespace: scanner.Namespace}
	var job batchv1.Job
	if err := r.Get(ctx, jobKey, &job); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if jobWasCreated(&scanner) {
			if statusErr := r.patchStatus(ctx, &scanner, func() {
				setTerminalStatus(&scanner, scanningv1alpha1.OutcomeFailed, "JobMissing", "scanner Job disappeared before reporting completion", now)
			}); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return r.reconcileTerminal(ctx, &scanner, now)
		}
		if !now.Before(notAfter) {
			if statusErr := r.patchStatus(ctx, &scanner, func() {
				setTerminalStatus(
					&scanner,
					scanningv1alpha1.OutcomeExpired,
					"ExecutionCutoffElapsed",
					"scan reached its absolute notAfter cutoff before Job creation",
					now,
				)
				meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
					Type:               scanningv1alpha1.ConditionAccepted,
					Status:             metav1.ConditionFalse,
					Reason:             "ExecutionCutoffElapsed",
					Message:            "notAfter elapsed before Job creation",
					ObservedGeneration: scanner.Generation,
				})
			}); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return r.reconcileTerminal(ctx, &scanner, now)
		}

		desiredJob, buildErr := buildJob(&scanner, r.JobConfig, now)
		if buildErr != nil {
			if statusErr := r.patchStatus(ctx, &scanner, func() {
				setTerminalStatus(&scanner, scanningv1alpha1.OutcomeFailed, "InvalidRequest", buildErr.Error(), now)
				meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
					Type:               scanningv1alpha1.ConditionAccepted,
					Status:             metav1.ConditionFalse,
					Reason:             "InvalidRequest",
					Message:            buildErr.Error(),
					ObservedGeneration: scanner.Generation,
				})
			}); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return r.reconcileTerminal(ctx, &scanner, now)
		}
		if createErr := r.Create(ctx, desiredJob); createErr != nil {
			if !apierrors.IsAlreadyExists(createErr) {
				return ctrl.Result{}, createErr
			}
			if getErr := r.Get(ctx, jobKey, &job); getErr != nil {
				return ctrl.Result{}, getErr
			}
		} else {
			job = *desiredJob
		}
	}

	if !metav1.IsControlledBy(&job, &scanner) {
		err := fmt.Errorf("deterministic Job name %q is already owned by another resource", job.Name)
		if statusErr := r.patchStatus(ctx, &scanner, func() {
			setTerminalStatus(&scanner, scanningv1alpha1.OutcomeFailed, "JobNameCollision", err.Error(), now)
		}); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	if !now.Before(notAfter) && !jobFinished(&job) {
		if err := r.requestJobDeletion(ctx, &scanner); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.patchStatus(ctx, &scanner, func() {
			setTerminalStatus(
				&scanner,
				scanningv1alpha1.OutcomeExpired,
				"ExecutionCutoffElapsed",
				"scan exceeded its absolute notAfter execution cutoff",
				now,
			)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	if !job.DeletionTimestamp.IsZero() && !jobFinished(&job) {
		if err := r.patchStatus(ctx, &scanner, func() {
			setTerminalStatus(&scanner, scanningv1alpha1.OutcomeFailed, "JobDeleted", "scanner Job was deleted before completion", now)
		}); err != nil {
			return ctrl.Result{}, err
		}
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	terminal, err := r.reflectJobStatus(ctx, &scanner, &job, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	if terminal {
		return r.reconcileTerminal(ctx, &scanner, now)
	}

	return ctrl.Result{}, nil
}

func (r *ScannerReconciler) reflectJobStatus(
	ctx context.Context,
	scanner *scanningv1alpha1.Scanner,
	job *batchv1.Job,
	now time.Time,
) (bool, error) {
	var completeCondition *batchv1.JobCondition
	var failedCondition *batchv1.JobCondition
	for i := range job.Status.Conditions {
		condition := &job.Status.Conditions[i]
		switch condition.Type {
		case batchv1.JobComplete:
			if condition.Status == corev1.ConditionTrue {
				completeCondition = condition
			}
		case batchv1.JobFailed:
			if condition.Status == corev1.ConditionTrue {
				failedCondition = condition
			}
		}
	}

	terminal := completeCondition != nil || failedCondition != nil
	err := r.patchStatus(ctx, scanner, func() {
		scanner.Status.ObservedGeneration = scanner.Generation
		if scanner.Status.QueuedAt == nil {
			queuedAt := metav1.NewTime(now)
			scanner.Status.QueuedAt = &queuedAt
		}
		meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
			Type:               scanningv1alpha1.ConditionAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             "Accepted",
			Message:            "scan request accepted",
			ObservedGeneration: scanner.Generation,
		})

		if completeCondition != nil {
			completedAt := completeCondition.LastTransitionTime
			if completedAt.IsZero() {
				completedAt = metav1.NewTime(now)
			}
			setTerminalStatus(scanner, scanningv1alpha1.OutcomeSucceeded, "JobSucceeded", "scanner Job completed successfully", completedAt.Time)
			return
		}
		if failedCondition != nil {
			completedAt := failedCondition.LastTransitionTime
			if completedAt.IsZero() {
				completedAt = metav1.NewTime(now)
			}
			setTerminalStatus(scanner, scanningv1alpha1.OutcomeFailed, "JobFailed", "scanner Job failed", completedAt.Time)
			return
		}

		scanner.Status.ActiveJobRef = &scanningv1alpha1.JobReference{
			Name:      job.Name,
			Namespace: job.Namespace,
			UID:       job.UID,
		}
		meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
			Type:               scanningv1alpha1.ConditionJobReady,
			Status:             metav1.ConditionTrue,
			Reason:             "JobCreated",
			Message:            "deterministic scanner Job exists",
			ObservedGeneration: scanner.Generation,
		})
		meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
			Type:               scanningv1alpha1.ConditionComplete,
			Status:             metav1.ConditionFalse,
			Reason:             "JobPending",
			Message:            "scanner Job has not completed",
			ObservedGeneration: scanner.Generation,
		})
		if job.Status.Active > 0 {
			scanner.Status.Outcome = scanningv1alpha1.OutcomeRunning
			if scanner.Status.StartedAt == nil {
				startedAt := metav1.NewTime(now)
				if job.Status.StartTime != nil {
					startedAt = *job.Status.StartTime.DeepCopy()
				}
				scanner.Status.StartedAt = &startedAt
			}
			meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
				Type:               scanningv1alpha1.ConditionComplete,
				Status:             metav1.ConditionFalse,
				Reason:             "JobRunning",
				Message:            "scanner Job is running",
				ObservedGeneration: scanner.Generation,
			})
		} else {
			scanner.Status.Outcome = scanningv1alpha1.OutcomePending
		}
	})
	return terminal, err
}

func setTerminalStatus(
	scanner *scanningv1alpha1.Scanner,
	outcome scanningv1alpha1.ScanOutcome,
	reason string,
	message string,
	when time.Time,
) {
	completedAt := metav1.NewTime(when.UTC())
	scanner.Status.ObservedGeneration = scanner.Generation
	scanner.Status.Outcome = outcome
	scanner.Status.ActiveJobRef = nil
	if scanner.Status.QueuedAt == nil && outcome != scanningv1alpha1.OutcomeExpired {
		queuedAt := completedAt.DeepCopy()
		scanner.Status.QueuedAt = queuedAt
	}
	scanner.Status.CompletedAt = &completedAt
	meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
		Type:               scanningv1alpha1.ConditionJobReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: scanner.Generation,
	})
	conditionStatus := metav1.ConditionFalse
	if outcome == scanningv1alpha1.OutcomeSucceeded {
		conditionStatus = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&scanner.Status.Conditions, metav1.Condition{
		Type:               scanningv1alpha1.ConditionComplete,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: scanner.Generation,
	})
}

func (r *ScannerReconciler) patchStatus(
	ctx context.Context,
	scanner *scanningv1alpha1.Scanner,
	mutate func(),
) error {
	before := scanner.DeepCopy()
	mutate()
	if reflect.DeepEqual(before.Status, scanner.Status) {
		return nil
	}
	return r.Status().Patch(ctx, scanner, client.MergeFrom(before))
}

func (r *ScannerReconciler) requestJobDeletion(ctx context.Context, scanner *scanningv1alpha1.Scanner) error {
	var job batchv1.Job
	key := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := r.Get(ctx, key, &job); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(&job, scanner) {
		return nil
	}
	if job.DeletionTimestamp.IsZero() {
		propagation := metav1.DeletePropagationBackground
		if err := r.Delete(ctx, &job, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil {
			return client.IgnoreNotFound(err)
		}
	}
	return nil
}

func (r *ScannerReconciler) releaseAndDeleteJob(ctx context.Context, scanner *scanningv1alpha1.Scanner) error {
	if err := r.releaseJobFinalizer(ctx, scanner); err != nil {
		return err
	}
	return r.requestJobDeletion(ctx, scanner)
}

func (r *ScannerReconciler) releaseJobFinalizer(ctx context.Context, scanner *scanningv1alpha1.Scanner) error {
	var job batchv1.Job
	key := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := r.Get(ctx, key, &job); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(&job, scanner) {
		return nil
	}
	if !containsString(job.Finalizers, jobFinalizer) {
		return nil
	}
	before := job.DeepCopy()
	job.Finalizers = removeString(job.Finalizers, jobFinalizer)
	return r.Patch(ctx, &job, client.MergeFrom(before))
}

func (r *ScannerReconciler) reconcileTerminal(
	ctx context.Context,
	scanner *scanningv1alpha1.Scanner,
	now time.Time,
) (ctrl.Result, error) {
	var err error
	if scanner.Status.Outcome == scanningv1alpha1.OutcomeCancelled ||
		scanner.Status.Outcome == scanningv1alpha1.OutcomeExpired {
		err = r.releaseAndDeleteJob(ctx, scanner)
	} else {
		err = r.releaseJobFinalizer(ctx, scanner)
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	if scanner.Status.CompletedAt == nil {
		return ctrl.Result{}, fmt.Errorf("terminal Scanner %s/%s has no completion timestamp", scanner.Namespace, scanner.Name)
	}
	deleteAt := scanner.Status.CompletedAt.Add(
		time.Duration(scanner.Spec.TTLSecondsAfterFinished) * time.Second,
	)
	if now.Before(deleteAt) {
		return ctrl.Result{RequeueAfter: deleteAt.Sub(now)}, nil
	}
	if err := r.Delete(ctx, scanner); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// The Scanner finalizer removes any owned Job before allowing deletion.
	return ctrl.Result{Requeue: true}, nil
}

func (r *ScannerReconciler) reconcileDeletion(ctx context.Context, scanner *scanningv1alpha1.Scanner) (ctrl.Result, error) {
	if !containsString(scanner.Finalizers, scannerFinalizer) {
		return ctrl.Result{}, nil
	}
	if err := r.requestJobDeletion(ctx, scanner); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.releaseJobFinalizer(ctx, scanner); err != nil {
		return ctrl.Result{}, err
	}

	var job batchv1.Job
	key := types.NamespacedName{Name: deterministicJobName(scanner), Namespace: scanner.Namespace}
	if err := r.Get(ctx, key, &job); err == nil {
		if metav1.IsControlledBy(&job, scanner) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	before := scanner.DeepCopy()
	scanner.Finalizers = removeString(scanner.Finalizers, scannerFinalizer)
	return ctrl.Result{}, r.Patch(ctx, scanner, client.MergeFrom(before))
}

func jobWasCreated(scanner *scanningv1alpha1.Scanner) bool {
	if scanner.Status.ActiveJobRef != nil {
		return true
	}
	condition := meta.FindStatusCondition(scanner.Status.Conditions, scanningv1alpha1.ConditionJobReady)
	return condition != nil && condition.Reason == "JobCreated"
}

func jobFinished(job *batchv1.Job) bool {
	for _, condition := range job.Status.Conditions {
		if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) &&
			condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func isTerminal(outcome scanningv1alpha1.ScanOutcome) bool {
	switch outcome {
	case scanningv1alpha1.OutcomeSucceeded,
		scanningv1alpha1.OutcomeFailed,
		scanningv1alpha1.OutcomeCancelled,
		scanningv1alpha1.OutcomeExpired:
		return true
	default:
		return false
	}
}

func containsString(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func removeString(values []string, value string) []string {
	result := make([]string, 0, len(values))
	for _, current := range values {
		if current != value {
			result = append(result, current)
		}
	}
	return result
}

// SetupWithManager registers the Scanner and owned Job watches.
func (r *ScannerReconciler) SetupWithManager(manager ctrl.Manager, maxConcurrent int) error {
	return ctrl.NewControllerManagedBy(manager).
		For(&scanningv1alpha1.Scanner{}).
		Owns(&batchv1.Job{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrent}).
		Named("scanner").
		Complete(r)
}
