// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Success;Duplicate;Invalid
type OIDCProviderStatus string

const (
	SuccessOIDCProviderStatus   = OIDCProviderStatus("Success")
	DuplicateOIDCProviderStatus = OIDCProviderStatus("Duplicate")
	InvalidOIDCProviderStatus   = OIDCProviderStatus("Invalid")
)

// OIDCProviderConfigSpec is a struct that describes an OIDC Provider.
type OIDCProviderConfigSpec struct {
	// Issuer is the OIDC Provider's issuer, per the OIDC Discovery Metadata document, as well as the
	// identifier that it will use for the iss claim in issued JWTs. This field will also be used as
	// the base URL for any endpoints used by the OIDC Provider (e.g., if your issuer is
	// https://example.com/foo, then your authorization endpoint will look like
	// https://example.com/foo/some/path/to/auth/endpoint).
	//
	// See
	// https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3 for more information.
	// +kubebuilder:validation:MinLength=1
	Issuer string `json:"issuer"`
}

// OIDCProviderConfigStatus is a struct that describes the actual state of an OIDC Provider.
type OIDCProviderConfigStatus struct {
	// Status holds an enum that describes the state of this OIDC Provider. Note that this Status can
	// represent success or failure.
	// +optional
	Status OIDCProviderStatus `json:"status,omitempty"`

	// Message provides human-readable details about the Status.
	// +optional
	Message string `json:"message,omitempty"`

	// LastUpdateTime holds the time at which the Status was last updated. It is a pointer to get
	// around some undesirable behavior with respect to the empty metav1.Time value (see
	// https://github.com/kubernetes/kubernetes/issues/86811).
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// JWKSSecret holds the name of the secret in which this OIDC Provider's signing/verification keys
	// are stored. If it is empty, then the signing/verification keys are either unknown or they don't
	// exist.
	// +optional
	JWKSSecret corev1.LocalObjectReference `json:"jwksSecret,omitempty"`
}

// OIDCProviderConfig describes the configuration of an OIDC provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=opc
type OIDCProviderConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec of the OIDC provider.
	Spec OIDCProviderConfigSpec `json:"spec"`

	// Status of the OIDC provider.
	Status OIDCProviderConfigStatus `json:"status,omitempty"`
}

// List of OIDCProviderConfig objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OIDCProviderConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OIDCProviderConfig `json:"items"`
}
