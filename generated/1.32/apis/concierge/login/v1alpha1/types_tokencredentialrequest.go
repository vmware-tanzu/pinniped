// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Specification of a TokenCredentialRequest, expected on requests to the Pinniped API.
type TokenCredentialRequestSpec struct {
	// Bearer token supplied with the credential request.
	Token string `json:"token,omitempty"`

	// Reference to an authenticator which can validate this credential request.
	Authenticator corev1.TypedLocalObjectReference `json:"authenticator"`
}

// Status of a TokenCredentialRequest, returned on responses to the Pinniped API.
type TokenCredentialRequestStatus struct {
	// A Credential will be returned for a successful credential request.
	// +optional
	Credential *ClusterCredential `json:"credential,omitempty"`

	// An error message will be returned for an unsuccessful credential request.
	// +optional
	Message *string `json:"message,omitempty"`
}

// TokenCredentialRequest submits an IDP-specific credential to Pinniped in exchange for a cluster-specific credential.
// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TokenCredentialRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TokenCredentialRequestSpec   `json:"spec,omitempty"`
	Status TokenCredentialRequestStatus `json:"status,omitempty"`
}

// TokenCredentialRequestList is a list of TokenCredentialRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TokenCredentialRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of TokenCredentialRequest.
	Items []TokenCredentialRequest `json:"items"`
}
