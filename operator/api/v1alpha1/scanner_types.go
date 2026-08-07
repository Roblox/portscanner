// Copyright 2026 Roblox Corporation
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ScanProfile selects a bounded scanner execution mode.
// +kubebuilder:validation:Enum=fast-full-tcp;targeted-tcp;deep
type ScanProfile string

const (
	ProfileFastFullTCP ScanProfile = "fast-full-tcp"
	ProfileTargetedTCP ScanProfile = "targeted-tcp"
	ProfileDeep        ScanProfile = "deep"
)

// ScanReason is the shared reason a scan entered the execution boundary.
// +kubebuilder:validation:Enum=new_target;policy_change;coverage;manual
type ScanReason string

const (
	ReasonNewTarget    ScanReason = "new_target"
	ReasonPolicyChange ScanReason = "policy_change"
	ReasonCoverage     ScanReason = "coverage"
	ReasonManual       ScanReason = "manual"
)

// ScanOutcome is the lifecycle result exposed by the operator. It never
// contains raw scan evidence.
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed;Cancelled;Expired
type ScanOutcome string

const (
	OutcomePending   ScanOutcome = "Pending"
	OutcomeRunning   ScanOutcome = "Running"
	OutcomeSucceeded ScanOutcome = "Succeeded"
	OutcomeFailed    ScanOutcome = "Failed"
	OutcomeCancelled ScanOutcome = "Cancelled"
	OutcomeExpired   ScanOutcome = "Expired"
)

const (
	ConditionAccepted = "Accepted"
	ConditionJobReady = "JobReady"
	ConditionComplete = "Complete"
)

// ScannerTarget is the single target represented by a Scanner resource.
type ScannerTarget struct {
	// Address is the canonical public IPv4 literal passed to the scanner. RFC
	// 5737 documentation addresses remain valid for examples and tests.
	// +kubebuilder:validation:Format=ipv4
	// +kubebuilder:validation:MinLength=7
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^([0-9]{1,3}[.]){3}[0-9]{1,3}$`
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('0.') && !self.startsWith('10.') && !self.startsWith('127.') && !self.startsWith('169.254.') && !self.startsWith('192.168.') && !self.matches('^100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]') && !self.matches('^172[.](1[6-9]|2[0-9]|3[01])[.]') && !self.matches('^198[.](18|19)[.]') && !self.matches('^(22[4-9]|23[0-9]|24[0-9]|25[0-5])[.]')",message="address must be a public IPv4 literal"
	Address string `json:"address"`

	// TargetID is the shared contract's deterministic target identifier.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	TargetID string `json:"targetId"`

	// Provider is the shared target's cloud provider.
	// +kubebuilder:validation:Enum=aws
	Provider string `json:"provider"`

	// ScopeID is the AWS account that owns the target.
	// +kubebuilder:validation:Pattern=`^[0-9]{12}$`
	ScopeID string `json:"scopeId"`

	// Location is the AWS region containing the target.
	// +kubebuilder:validation:MinLength=9
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`
	Location string `json:"location"`

	// ResourceID is the AWS network interface identifier.
	// +kubebuilder:validation:MinLength=12
	// +kubebuilder:validation:MaxLength=36
	// +kubebuilder:validation:Pattern=`^eni-[0-9a-f]{8,32}$`
	ResourceID string `json:"resourceId"`

	// PrivateAddress is the target's canonical source-side IPv4 address.
	// +kubebuilder:validation:Format=ipv4
	// +kubebuilder:validation:MinLength=7
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^([0-9]{1,3}[.]){3}[0-9]{1,3}$`
	PrivateAddress string `json:"privateAddress"`

	// Generation identifies the source-side revision of this target.
	// +kubebuilder:validation:Minimum=1
	Generation int64 `json:"generation"`
}

// PortRange is an inclusive TCP port range.
type PortRange struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// SourceTimestamps retain the source event's timing independently from
// Kubernetes object timestamps.
type SourceTimestamps struct {
	// EventAt is when the source event occurred.
	EventAt metav1.Time `json:"eventAt"`

	// ObservedAt is when the source observed the target state.
	ObservedAt metav1.Time `json:"observedAt"`
}

// ScannerSpec defines one bounded, one-shot scan request.
// +kubebuilder:validation:XValidation:rule="self.profile != 'targeted-tcp' || (has(self.ports) && size(self.ports) > 0) || (has(self.ranges) && size(self.ranges) > 0)",message="targeted-tcp requires at least one port or range"
// +kubebuilder:validation:XValidation:rule="!has(self.ranges) || self.ranges.all(r, r.start <= r.end)",message="each port range start must be less than or equal to end"
// +kubebuilder:validation:XValidation:rule="self.target == oldSelf.target && self.eventId == oldSelf.eventId && self.directiveId == oldSelf.directiveId && self.traceId == oldSelf.traceId && self.reason == oldSelf.reason && self.profile == oldSelf.profile && ((!has(self.ports) && !has(oldSelf.ports)) || (has(self.ports) && has(oldSelf.ports) && self.ports == oldSelf.ports)) && ((!has(self.ranges) && !has(oldSelf.ranges)) || (has(self.ranges) && has(oldSelf.ranges) && self.ranges == oldSelf.ranges)) && self.priority == oldSelf.priority && self.deadline == oldSelf.deadline && self.notAfter == oldSelf.notAfter && self.sourceTimestamps == oldSelf.sourceTimestamps && self.retryLimit == oldSelf.retryLimit && self.ttlSecondsAfterFinished == oldSelf.ttlSecondsAfterFinished",message="scan execution fields are immutable; only cancel may change"
type ScannerSpec struct {
	// Target is the only scan target for this resource.
	Target ScannerTarget `json:"target"`

	// EventID is the shared contract's deterministic source event identifier.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	EventID string `json:"eventId"`

	// DirectiveID is the shared contract's deterministic scan directive identifier.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	DirectiveID string `json:"directiveId"`

	// TraceID correlates logs and result transport across systems.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$`
	TraceID string `json:"traceId"`

	// Reason describes why the scan was requested.
	Reason ScanReason `json:"reason"`

	// Profile selects scanner behavior.
	Profile ScanProfile `json:"profile"`

	// Ports is an explicit set of TCP ports. Values are deduplicated before
	// being passed to the scanner.
	// +kubebuilder:validation:MaxItems=65535
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// +listType=set
	Ports []int32 `json:"ports,omitempty"`

	// Ranges is an explicit set of inclusive TCP port ranges.
	// +kubebuilder:validation:MaxItems=1024
	Ranges []PortRange `json:"ranges,omitempty"`

	// Priority is mapped to the configured high or normal PriorityClass.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Deadline is the request deadline. The earlier of Deadline and NotAfter
	// becomes the Job active deadline.
	Deadline metav1.Time `json:"deadline"`

	// NotAfter is the source event's absolute expiry time.
	NotAfter metav1.Time `json:"notAfter"`

	// SourceTimestamps records source event timing.
	SourceTimestamps SourceTimestamps `json:"sourceTimestamps"`

	// RetryLimit maps to Job backoffLimit.
	// +kubebuilder:default=0
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=6
	RetryLimit int32 `json:"retryLimit,omitempty"`

	// TTLSecondsAfterFinished controls cleanup of the completed Job.
	// +kubebuilder:default=3600
	// +kubebuilder:validation:Minimum=0
	TTLSecondsAfterFinished int32 `json:"ttlSecondsAfterFinished,omitempty"`

	// Cancel requests cancellation without deleting the Scanner resource.
	Cancel bool `json:"cancel,omitempty"`
}

// JobReference identifies the Job while it is active.
type JobReference struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	UID       types.UID `json:"uid,omitempty"`
}

// ScannerStatus exposes execution lifecycle only, never raw scan evidence.
type ScannerStatus struct {
	// ObservedGeneration is the latest Scanner generation processed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Outcome is the current lifecycle outcome.
	Outcome ScanOutcome `json:"outcome,omitempty"`

	// ActiveJobRef points at the pending or running Job.
	ActiveJobRef *JobReference `json:"activeJobRef,omitempty"`

	// QueuedAt is when the operator accepted the request.
	QueuedAt *metav1.Time `json:"queuedAt,omitempty"`

	// StartedAt is when the Job first became active.
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CompletedAt is when execution reached a terminal outcome.
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// Conditions summarize acceptance, Job availability, and completion.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=scan,categories=portscanner
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Outcome",type=string,JSONPath=`.status.outcome`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Scanner represents exactly one target and at most one Kubernetes Job.
type Scanner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScannerSpec   `json:"spec,omitempty"`
	Status ScannerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ScannerList contains a list of Scanner resources.
type ScannerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Scanner `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Scanner{}, &ScannerList{})
}
