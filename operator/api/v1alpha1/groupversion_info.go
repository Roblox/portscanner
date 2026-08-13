// SPDX-FileCopyrightText: 2026 Portscanner contributors
// SPDX-License-Identifier: MIT

// Package v1alpha1 contains the public Scanner API.
// +kubebuilder:object:generate=true
// +groupName=scanning.portscanner.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion identifies this API version.
	GroupVersion = schema.GroupVersion{Group: "scanning.portscanner.io", Version: "v1alpha1"}

	// SchemeBuilder registers Scanner API types.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds Scanner API types to a runtime Scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
