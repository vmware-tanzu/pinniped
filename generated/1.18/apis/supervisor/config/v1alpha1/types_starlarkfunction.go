// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Success;LoadError;TestFailure
type StarlarkFunctionStatusCondition string

// +kubebuilder:validation:Enum=usernameAndGroups.transform.pinniped.dev/v1
type StarlarkFunctionType string

const (
	SuccessStarlarkFunctionStatusCondition     = StarlarkFunctionStatusCondition("Success")
	LoadErrorStarlarkFunctionStatusCondition   = StarlarkFunctionStatusCondition("LoadError")
	TestFailureStarlarkFunctionStatusCondition = StarlarkFunctionStatusCondition("TestFailure")

	UsernameAndGroupsTransformationV1StarlarkFunctionType = StarlarkFunctionType("usernameAndGroups.transform.pinniped.dev/v1")
)

// StarlarkFunctionStatus describes the actual state of a StarlarkFunction resource.
type StarlarkFunctionStatus struct {
	// Status holds an enum that describes the state of this resource. Note that this Status can
	// represent success or failure.
	// +optional
	Status StarlarkFunctionStatusCondition `json:"status,omitempty"`

	// Message provides human-readable details about the Status.
	// +optional
	Message string `json:"message,omitempty"`

	// LastUpdateTime holds the time at which the Status was last updated. It is a pointer to get
	// around some undesirable behavior with respect to the empty metav1.Time value (see
	// https://github.com/kubernetes/kubernetes/issues/86811).
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`
}

// StarlarkFunctionParam defines an additional param for a StarlarkFunction script.
type StarlarkFunctionParam struct {
	// Name is the name of the param. This name can be used to pass a value for this param.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Type is the type of the param. When a value is passed for this param, the value's type
	// must match the declared type for the param.
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`
}

// StarlarkFunctionSpec is the spec for a StarlarkFunction script.
type StarlarkFunctionSpec struct {
	// The type of transformation decides where it is appropriate to use, what inputs are passed to
	// the script, and what outputs are expected for the script to return. All transformable inputs
	// are also returned as outputs, which allows the chaining of multiple transform functions of
	// the same type. The available types are defined as constants and are not user-defined.
	Type StarlarkFunctionType `json:"type"`

	// AdditionalParams declare what additional params are allowed. These are metadata to assist
	// in the business logic of the transform function, but are not returned by the transform
	// function because they are immutable and each call in the chain will define their own
	// metadata param values. They will be passed to the function as extra params in the same
	// order that they are defined here.
	// +optional
	AdditionalParams []StarlarkFunctionParam `json:"additionalParams,omitempty"`

	// Script is the Starlark source code of this StarlarkFunction. It must include a function
	// whose name and input params match those of the function's Type, plus accept any additional
	// params listed by AdditionalParams.
	//
	// Starlark is a simplified dialect of Python, and therefore whitespace indentation is meaningful.
	// Please exercise caution to ensure that the whitespace of the script is preserved when setting
	// the value of this field.
	//
	// The documentation for the Starlark programming language dialect used by Pinniped can be found at
	// https://github.com/google/starlark-go/blob/master/doc/spec.md. Pinniped enables the Set type and
	// related functions for use in these scripts, which is an extension of the Starlark standard.
	// Consistent with the Starlark standard, if, for, and while statements are not permitted at the
	// top level, and top-level rebindings are not permitted.
	// +kubebuilder:validation:MinLength=1
	Script string `json:"script"`
}

// StarlarkFunction is a Starlark script.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped
// +kubebuilder:subresource:status
type StarlarkFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec of the StarlarkFunction.
	Spec StarlarkFunctionSpec `json:"spec"`

	// Status of StarlarkFunction.
	Status StarlarkFunctionStatus `json:"status,omitempty"`
}

// List of StarlarkFunction objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type StarlarkFunctionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []StarlarkFunction `json:"items"`
}
