// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OIDCIdentityProviderPhase string

const (
	// PhasePending is the default phase for newly-created OIDCIdentityProvider resources.
	PhasePending OIDCIdentityProviderPhase = "Pending"

	// PhaseReady is the phase for an OIDCIdentityProvider resource in a healthy state.
	PhaseReady OIDCIdentityProviderPhase = "Ready"

	// PhaseError is the phase for an OIDCIdentityProvider in an unhealthy state.
	PhaseError OIDCIdentityProviderPhase = "Error"
)

// Status of an OIDC identity provider.
type OIDCIdentityProviderStatus struct {
	// Phase summarizes the overall status of the OIDCIdentityProvider.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase OIDCIdentityProviderPhase `json:"phase,omitempty"`

	// Represents the observations of an identity provider's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// OIDCAuthorizationConfig provides information about how to form the OAuth2 authorization
// request parameters.
type OIDCAuthorizationConfig struct {
	// AdditionalScopes are the scopes in addition to "openid" that will be requested as part of the authorization
	// request flow with an OIDC identity provider.
	// In the case of a Resource Owner Password Credentials Grant flow, AdditionalScopes are the scopes
	// in addition to "openid" that will be requested as part of the token request (see also the AllowPasswordGrant field).
	// By default, only the "openid" scope will be requested.
	// +optional
	AdditionalScopes []string `json:"additionalScopes,omitempty"`

	// AllowPasswordGrant, when true, will allow the use of OAuth 2.0's Resource Owner Password Credentials Grant
	// (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) to authenticate to the OIDC provider using a
	// username and password without a web browser, in addition to the usual browser-based OIDC Authorization Code Flow.
	// The Resource Owner Password Credentials Grant is not officially part of the OIDC specification, so it may not be
	// supported by your OIDC provider. If your OIDC provider supports returning ID tokens from a Resource Owner Password
	// Credentials Grant token request, then you can choose to set this field to true. This will allow end users to choose
	// to present their username and password to the kubectl CLI (using the Pinniped plugin) to authenticate to the
	// cluster, without using a web browser to log in as is customary in OIDC Authorization Code Flow. This may be
	// convenient for users, especially for identities from your OIDC provider which are not intended to represent a human
	// actor, such as service accounts performing actions in a CI/CD environment. Even if your OIDC provider supports it,
	// you may wish to disable this behavior by setting this field to false when you prefer to only allow users of this
	// OIDCIdentityProvider to log in via the browser-based OIDC Authorization Code Flow. Using the Resource Owner Password
	// Credentials Grant means that the Pinniped CLI and Pinniped Supervisor will directly handle your end users' passwords
	// (similar to LDAPIdentityProvider), and you will not be able to require multi-factor authentication or use the other
	// web-based login features of your OIDC provider during Resource Owner Password Credentials Grant logins.
	// AllowPasswordGrant defaults to false.
	// +optional
	AllowPasswordGrant bool `json:"allowPasswordGrant,omitempty"`
}

// OIDCClaims provides a mapping from upstream claims into identities.
type OIDCClaims struct {
	// Groups provides the name of the token claim that will be used to ascertain the groups to which
	// an identity belongs.
	// +optional
	Groups string `json:"groups"`

	// Username provides the name of the token claim that will be used to ascertain an identity's
	// username.
	// +optional
	Username string `json:"username"`
}

// OIDCClient contains information about an OIDC client (e.g., client ID and client
// secret).
type OIDCClient struct {
	// SecretName contains the name of a namespace-local Secret object that provides the clientID and
	// clientSecret for an OIDC client. If only the SecretName is specified in an OIDCClient
	// struct, then it is expected that the Secret is of type "secrets.pinniped.dev/oidc-client" with keys
	// "clientID" and "clientSecret".
	SecretName string `json:"secretName"`
}

// Spec for configuring an OIDC identity provider.
type OIDCIdentityProviderSpec struct {
	// Issuer is the issuer URL of this OIDC identity provider, i.e., where to fetch
	// /.well-known/openid-configuration.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Issuer string `json:"issuer"`

	// TLS configuration for discovery/JWKS requests to the issuer.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`

	// AuthorizationConfig holds information about how to form the OAuth2 authorization request
	// parameters to be used with this OIDC identity provider.
	// +optional
	AuthorizationConfig OIDCAuthorizationConfig `json:"authorizationConfig,omitempty"`

	// Claims provides the names of token claims that will be used when inspecting an identity from
	// this OIDC identity provider.
	// +optional
	Claims OIDCClaims `json:"claims"`

	// OIDCClient contains OIDC client information to be used used with this OIDC identity
	// provider.
	Client OIDCClient `json:"client"`
}

// OIDCIdentityProvider describes the configuration of an upstream OpenID Connect identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type OIDCIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec OIDCIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status OIDCIdentityProviderStatus `json:"status,omitempty"`
}

// List of OIDCIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OIDCIdentityProvider `json:"items"`
}
