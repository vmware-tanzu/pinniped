/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Status of a webhook identity provider.
type WebhookIdentityProviderStatus struct {
	// Represents the observations of an identity provider's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// Spec for configuring a webhook identity provider.
type WebhookIdentityProviderSpec struct {
	// Webhook server endpoint URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint"`

	// TLS configuration.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// WebhookIdentityProvider describes the configuration of a Pinniped webhook identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=all;idp;idps,shortName=webhookidp;webhookidps
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.spec.endpoint`
type WebhookIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec WebhookIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status WebhookIdentityProviderStatus `json:"status,omitempty"`
}

// List of WebhookIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type WebhookIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WebhookIdentityProvider `json:"items"`
}
