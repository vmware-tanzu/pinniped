// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Status of a webhook authenticator.
type WebhookAuthenticatorStatus struct {
	// Represents the observations of the authenticator's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// Spec for configuring a webhook authenticator.
type WebhookAuthenticatorSpec struct {
	// Webhook server endpoint URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint"`

	// TLS configuration.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// WebhookAuthenticator describes the configuration of a webhook authenticator.
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-authenticator;pinniped-authenticators,scope=Cluster
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.spec.endpoint`
// +kubebuilder:subresource:status
type WebhookAuthenticator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the authenticator.
	Spec WebhookAuthenticatorSpec `json:"spec"`

	// Status of the authenticator.
	Status WebhookAuthenticatorStatus `json:"status,omitempty"`
}

// List of WebhookAuthenticator objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type WebhookAuthenticatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WebhookAuthenticator `json:"items"`
}
