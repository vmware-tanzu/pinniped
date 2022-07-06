// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type OIDCClientPhase string

const (
	// PhasePending is the default phase for newly-created OIDCClient resources.
	PhasePending OIDCClientPhase = "Pending"

	// PhaseReady is the phase for an OIDCClient resource in a healthy state.
	PhaseReady OIDCClientPhase = "Ready"

	// PhaseError is the phase for an OIDCClient in an unhealthy state.
	PhaseError OIDCClientPhase = "Error"
)

// +kubebuilder:validation:Pattern=`^https://.+|^http://(127\.0\.0\.1|\[::1\])(:\d+)?/`
type RedirectURI string

// +kubebuilder:validation:Enum="authorization_code";"refresh_token";"urn:ietf:params:oauth:grant-type:token-exchange"
type GrantType string

// +kubebuilder:validation:Enum="openid";"offline_access";"username";"groups";"pinniped:request-audience"
type Scope string

// OIDCClientSpec is a struct that describes an OIDCClient.
type OIDCClientSpec struct {
	// allowedRedirectURIs is a list of the allowed redirect_uri param values that should be accepted during OIDC flows with this
	// client. Any other uris will be rejected.
	// Must be a URI with the https scheme, unless the hostname is 127.0.0.1 or ::1 which may use the http scheme.
	// Port numbers are not required for 127.0.0.1 or ::1 and are ignored when checking for a matching redirect_uri.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	AllowedRedirectURIs []RedirectURI `json:"allowedRedirectURIs"`

	// allowedGrantTypes is a list of the allowed grant_type param values that should be accepted during OIDC flows with this
	// client.
	//
	// Must only contain the following values:
	// - authorization_code: allows the client to perform the authorization code grant flow, i.e. allows the webapp to
	//   authenticate users. This grant must always be listed.
	// - refresh_token: allows the client to perform refresh grants for the user to extend the user's session.
	//   This grant must be listed if allowedScopes lists offline_access.
	// - urn:ietf:params:oauth:grant-type:token-exchange: allows the client to perform RFC8693 token exchange,
	//   which is a step in the process to be able to get a cluster credential for the user.
	//   This grant must be listed if allowedScopes lists pinniped:request-audience.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	AllowedGrantTypes []GrantType `json:"allowedGrantTypes"`

	// allowedScopes is a list of the allowed scopes param values that should be accepted during OIDC flows with this client.
	//
	// Must only contain the following values:
	// - openid: The client is allowed to request ID tokens. ID tokens only include the required claims by default (iss, sub, aud, exp, iat).
	//   This scope must always be listed.
	// - offline_access: The client is allowed to request an initial refresh token during the authorization code grant flow.
	//   This scope must be listed if allowedGrantTypes lists refresh_token.
	// - pinniped:request-audience: The client is allowed to request a new audience value during a RFC8693 token exchange,
	//   which is a step in the process to be able to get a cluster credential for the user.
	//   openid, username and groups scopes must be listed when this scope is present.
	//   This scope must be listed if allowedGrantTypes lists urn:ietf:params:oauth:grant-type:token-exchange.
	// - username: The client is allowed to request that ID tokens contain the user's username.
	//   Without the username scope being requested and allowed, the ID token will not contain the user's username.
	// - groups: The client is allowed to request that ID tokens contain the user's group membership,
	//   if their group membership is discoverable by the Supervisor.
	//   Without the groups scope being requested and allowed, the ID token will not contain groups.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	AllowedScopes []Scope `json:"allowedScopes"`
}

// OIDCClientStatus is a struct that describes the actual state of an OIDCClient.
type OIDCClientStatus struct {
	// phase summarizes the overall status of the OIDCClient.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase OIDCClientPhase `json:"phase,omitempty"`

	// conditions represent the observations of an OIDCClient's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// totalClientSecrets is the current number of client secrets that are detected for this OIDCClient.
	TotalClientSecrets int `json:"totalClientSecrets"`
}

// OIDCClient describes the configuration of an OIDC client.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec of the OIDC client.
	Spec OIDCClientSpec `json:"spec"`

	// Status of the OIDC client.
	Status OIDCClientStatus `json:"status,omitempty"`
}

// List of OIDCClient objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OIDCClient `json:"items"`
}
