// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClientSpec is a struct that describes an OIDC Client.
type OIDCClientSpec struct {
	// allowedRedirectURIs is a list of the allowed redirect_uri param values that should be accepted during OIDC flows with this
	// client. Any other uris will be rejected.
	// Must be https, unless it is a loopback.
	// +kubebuilder:validation:MinItems=1
	AllowedRedirectURIs []string `json:"allowedRedirectURIs"`

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
	// +kubebuilder:validation:MinItems=1
	AllowedGrantTypes []string `json:"allowedGrantTypes"`

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
	// +kubebuilder:validation:MinItems=1
	AllowedScopes []string `json:"allowedScopes"`
}

// OIDCClientStatus is a struct that describes the actual state of an OIDC Client.
type OIDCClientStatus struct {
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
