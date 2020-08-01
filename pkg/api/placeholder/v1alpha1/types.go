/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type LoginCredentialType string

const (
	TokenLoginCredentialType = LoginCredentialType("token")
)

type LoginRequestTokenCredential struct {
	// Value of the bearer token supplied with the login request.
	Value string `json:"value,omitempty" protobuf:"bytes,1,opt,name=value"`
}

type LoginRequestSpec struct {
	// Type of credential.
	Type LoginCredentialType `json:"type,omitempty" protobuf:"bytes,1,opt,name=type"`

	// Token credential (when Type == TokenLoginCredentialType).
	Token *LoginRequestTokenCredential `json:"token,omitempty" protobuf:"bytes,2,opt,name=token"`
}

type LoginRequestCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time `json:"expirationTimestamp,omitempty"`

	// Token is a bearer token used by the client for request authentication.
	Token string `json:"token,omitempty"`

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string `json:"clientCertificateData,omitempty"`

	// PEM-encoded private key for the above certificate.
	ClientKeyData string `json:"clientKeyData,omitempty"`
}

type User struct {
	// Identity Provider name for authenticated user.
	Name string `json:"name,omitempty"`

	// Identity Provider groups for authenticated user.
	Groups []string `json:"groups"`
}

type LoginRequestStatus struct {
	// A Credential will be returned for a successful login request.
	// +optional
	Credential *LoginRequestCredential `json:"credential,omitempty"`

	// A User will be populated from the Identity Provider.
	// +optional
	User *User `json:"user,omitempty"`

	// An error message will be returned for an unsuccessful login request.
	// +optional
	Message string `json:"message,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type LoginRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec   LoginRequestSpec   `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
	Status LoginRequestStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LoginRequestList is a list of LoginRequest objects.
type LoginRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []LoginRequest `json:"items" protobuf:"bytes,2,rep,name=items"`
}

type LoginDiscoveryConfigSpec struct {
	// The K8s API server URL. Required.
	Server string `json:"server,omitempty"`

	// The K8s API server CA bundle. Required.
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type LoginDiscoveryConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec LoginDiscoveryConfigSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type LoginDiscoveryConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LoginDiscoveryConfig `json:"items"`
}
