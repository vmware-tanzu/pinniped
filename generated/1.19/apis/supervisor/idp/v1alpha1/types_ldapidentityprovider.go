// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LDAPIdentityProviderPhase string

const (
	// LDAPPhasePending is the default phase for newly-created LDAPIdentityProvider resources.
	LDAPPhasePending LDAPIdentityProviderPhase = "Pending"

	// LDAPPhaseReady is the phase for an LDAPIdentityProvider resource in a healthy state.
	LDAPPhaseReady LDAPIdentityProviderPhase = "Ready"

	// LDAPPhaseError is the phase for an LDAPIdentityProvider in an unhealthy state.
	LDAPPhaseError LDAPIdentityProviderPhase = "Error"
)

// Status of an LDAP identity provider.
type LDAPIdentityProviderStatus struct {
	// Phase summarizes the overall status of the LDAPIdentityProvider.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase LDAPIdentityProviderPhase `json:"phase,omitempty"`
}

// Spec for configuring an LDAP identity provider.
type LDAPIdentityProviderSpec struct {
	// Host is the hostname of this LDAP identity provider, i.e., where to connect. For example: ldap.example.com:636.
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
}

// LDAPIdentityProvider describes the configuration of an upstream Lightweight Directory Access
// Protocol (LDAP) identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type LDAPIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec LDAPIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status LDAPIdentityProviderStatus `json:"status,omitempty"`
}

// List of LDAPIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type LDAPIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LDAPIdentityProvider `json:"items"`
}
