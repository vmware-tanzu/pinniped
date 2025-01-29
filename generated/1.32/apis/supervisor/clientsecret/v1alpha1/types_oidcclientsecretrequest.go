// Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClientSecretRequest can be used to update the client secrets associated with an OIDCClient.
// +genclient
// +genclient:onlyVerbs=create
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"` // metadata.name must be set to the client ID

	Spec OIDCClientSecretRequestSpec `json:"spec"`

	// +optional
	Status OIDCClientSecretRequestStatus `json:"status"`
}

// Spec of the OIDCClientSecretRequest.
type OIDCClientSecretRequestSpec struct {
	// Request a new client secret to for the OIDCClient referenced by the metadata.name field.
	// +optional
	GenerateNewSecret bool `json:"generateNewSecret"`

	// Revoke the old client secrets associated with the OIDCClient referenced by the metadata.name field.
	// +optional
	RevokeOldSecrets bool `json:"revokeOldSecrets"`
}

// Status of the OIDCClientSecretRequest.
type OIDCClientSecretRequestStatus struct {
	// The unencrypted OIDC Client Secret. This will only be shared upon creation and cannot be recovered if lost.
	GeneratedSecret string `json:"generatedSecret,omitempty"`

	// The total number of client secrets associated with the OIDCClient referenced by the metadata.name field.
	TotalClientSecrets int `json:"totalClientSecrets"`
}

// OIDCClientSecretRequestList is a list of OIDCClientSecretRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of OIDCClientSecretRequest.
	Items []OIDCClientSecretRequest `json:"items"`
}
