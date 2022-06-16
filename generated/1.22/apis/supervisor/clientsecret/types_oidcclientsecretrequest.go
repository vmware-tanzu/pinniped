// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientsecret

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type OIDCClientSecretRequestSpec struct {
	// Request a new client secret to for the OIDCClient referenced by the metadata.name field.
	GenerateNewSecret bool `json:"generateNewSecret"`

	// Revoke the old client secrets associated with the OIDCClient referenced by the metadata.name
	// field.
	RevokeOldSecrets bool `json:"revokeOldSecrets"`
}

type OIDCClientSecretRequestStatus struct {
	// The unencrypted OIDC Client Secret. This will only be shared upon creation and cannot
	// be recovered if you lose it.
	GeneratedSecret string `json:"generatedSecret,omitempty"`

	// The total number of client secrets associated with the OIDCClient referenced by the
	// metadata.name field.
	TotalClientSecrets int `json:"totalClientSecrets"`
}

// OIDCClientSecretRequest can be used to update the client secrets associated with an
// OIDCClient.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"` // metadata.name must be set to the client ID

	Spec   OIDCClientSecretRequestSpec   `json:"spec"`
	Status OIDCClientSecretRequestStatus `json:"status"`
}

// OIDCClientSecretList is a list of OIDCClientSecretRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of OIDCClientSecretRequest
	Items []OIDCClientSecretRequest
}
