/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package pinniped

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type CredentialType string

const (
	TokenCredentialType = CredentialType("token")
)

type CredentialRequestTokenCredential struct {
	// Value of the bearer token supplied with the credential request.
	Value string
}

type CredentialRequestSpec struct {
	// Type of credential.
	Type CredentialType

	// Token credential (when Type == TokenCredentialType).
	Token *CredentialRequestTokenCredential
}

type CredentialRequestCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time

	// Token is a bearer token used by the client for request authentication.
	Token string

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string

	// PEM-encoded private key for the above certificate.
	ClientKeyData string
}

type CredentialRequestStatus struct {
	// A Credential will be returned for a successful credential request.
	// +optional
	Credential *CredentialRequestCredential

	// An error message will be returned for an unsuccessful credential request.
	// +optional
	Message *string
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialRequest struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CredentialRequestSpec
	Status CredentialRequestStatus
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialRequestList is a list of CredentialRequest objects.
type CredentialRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of CredentialRequests
	Items []CredentialRequest
}
