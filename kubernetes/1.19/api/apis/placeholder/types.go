/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package placeholder

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type LoginCredentialType string

const (
	TokenLoginCredentialType = LoginCredentialType("token")
)

type LoginRequestTokenCredential struct {
	// Value of the bearer token supplied with the login request.
	Value string
}

type LoginRequestSpec struct {
	// Type of credential.
	Type LoginCredentialType

	// Token credential (when Type == TokenLoginCredentialType).
	Token *LoginRequestTokenCredential
}

type LoginRequestCredential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp metav1.Time

	// Token is a bearer token used by the client for request authentication.
	Token string

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string

	// PEM-encoded private key for the above certificate.
	ClientKeyData string
}

type User struct {
	// Identity Provider name for authenticated user.
	Name string

	// Identity Provider groups for authenticated user.
	Groups []string
}

type LoginRequestStatus struct {
	// A Credential will be returned for a successful login request.
	// +optional
	Credential *LoginRequestCredential

	// A User will be populated from the Identity Provider.
	// +optional
	User *User

	// An error message will be returned for an unsuccessful login request.
	// +optional
	Message *string
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type LoginRequest struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   LoginRequestSpec
	Status LoginRequestStatus
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LoginRequestList is a list of LoginRequest objects.
type LoginRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of LoginRequests
	Items []LoginRequest
}
