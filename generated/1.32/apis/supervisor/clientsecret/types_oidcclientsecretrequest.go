// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientsecret

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClientSecretRequest can be used to update the client secrets associated with an OIDCClient.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequest struct {
	metav1.TypeMeta
	metav1.ObjectMeta // metadata.name must be set to the client ID

	Spec OIDCClientSecretRequestSpec

	// +optional
	Status OIDCClientSecretRequestStatus
}

// Spec of the OIDCClientSecretRequest.
type OIDCClientSecretRequestSpec struct {
	// Request a new client secret to for the OIDCClient referenced by the metadata.name field.
	// +optional
	GenerateNewSecret bool

	// Revoke the old client secrets associated with the OIDCClient referenced by the metadata.name field.
	// +optional
	RevokeOldSecrets bool
}

// Status of the OIDCClientSecretRequest.
type OIDCClientSecretRequestStatus struct {
	// The unencrypted OIDC Client Secret. This will only be shared upon creation and cannot be recovered if lost.
	GeneratedSecret string

	// The total number of client secrets associated with the OIDCClient referenced by the metadata.name field.
	TotalClientSecrets int
}

// OIDCClientSecretRequestList is a list of OIDCClientSecretRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of OIDCClientSecretRequest.
	Items []OIDCClientSecretRequest
}
