/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type CredentialType string

const (
	TokenCredentialType = CredentialType("token")
)

// CredentialRequestTokenCredential holds a bearer token issued by an upstream identity provider.
type CredentialRequestTokenCredential struct {
	// Value of the bearer token supplied with the credential request.
	Value string `json:"value,omitempty"`
}

// CredentialRequestSpec is the specification of a CredentialRequest, expected on requests to the Pinniped API
type CredentialRequestSpec struct {
	// Type of credential.
	Type CredentialType `json:"type,omitempty"`

	// Token credential (when Type == TokenCredentialType).
	Token *CredentialRequestTokenCredential `json:"token,omitempty"`
}

// CredentialRequestCredential is the cluster-specific credential returned on a successful CredentialRequest. It
// contains either a valid bearer token or a valid TLS certificate and corresponding private key for the cluster.
type CredentialRequestCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time `json:"expirationTimestamp,omitempty"`

	// Token is a bearer token used by the client for request authentication.
	Token string `json:"token,omitempty"`

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string `json:"clientCertificateData,omitempty"`

	// PEM-encoded private key for the above certificate.
	ClientKeyData string `json:"clientKeyData,omitempty"`
}

// CredentialRequestStatus is the status of a CredentialRequest, returned on responses to the Pinniped API.
type CredentialRequestStatus struct {
	// A Credential will be returned for a successful credential request.
	// +optional
	Credential *CredentialRequestCredential `json:"credential,omitempty"`

	// An error message will be returned for an unsuccessful credential request.
	// +optional
	Message *string `json:"message,omitempty"`
}

// CredentialRequest submits an IDP-specific credential to Pinniped in exchange for a cluster-specific credential.
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CredentialRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CredentialRequestSpec   `json:"spec,omitempty"`
	Status CredentialRequestStatus `json:"status,omitempty"`
}


// CredentialRequestList is a list of CredentialRequest objects.
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CredentialRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialRequest `json:"items"`
}
