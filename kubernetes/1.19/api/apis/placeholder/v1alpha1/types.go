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

type CredentialRequestTokenCredential struct {
	// Value of the bearer token supplied with the credential request.
	Value string `json:"value,omitempty" protobuf:"bytes,1,opt,name=value"`
}

type CredentialRequestSpec struct {
	// Type of credential.
	Type CredentialType `json:"type,omitempty" protobuf:"bytes,1,opt,name=type"`

	// Token credential (when Type == TokenCredentialType).
	Token *CredentialRequestTokenCredential `json:"token,omitempty" protobuf:"bytes,2,opt,name=token"`
}

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

type CredentialRequestStatus struct {
	// A Credential will be returned for a successful credential request.
	// +optional
	Credential *CredentialRequestCredential `json:"credential,omitempty"`

	// An error message will be returned for an unsuccessful credential request.
	// +optional
	Message *string `json:"message,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   CredentialRequestSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status CredentialRequestStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialRequestList is a list of CredentialRequest objects.
type CredentialRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []CredentialRequest `json:"items" protobuf:"bytes,2,rep,name=items"`
}
