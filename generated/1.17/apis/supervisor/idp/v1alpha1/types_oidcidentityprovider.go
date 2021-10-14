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

// OIDCIdentityProviderStatus is the status of an OIDC identity provider.
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
	// DoNotRequestOfflineAccess determines if the "offline_access" scope will be requested from your OIDC provider in
	// the authorization request during an OIDC Authorization Code Flow and in the token request during a Resource Owner
	// Password Credentials Grant in order to ask to receive a refresh token in the response. Starting in v0.13.0, the
	// Pinniped Supervisor requires that your OIDC provider returns refresh tokens to the Supervisor from these
	// authorization flows. For most OIDC providers, the scope required to receive refresh tokens will be "offline_access".
	// See https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess for a description of the "offline_access"
	// scope. See the documentation of your OIDC provider's authorization and token endpoints for its requirements for what
	// to include in the request in order to receive a refresh token in the response, if anything. By default,
	// DoNotRequestOfflineAccess is false, which means that "offline_access" will be sent in the authorization request,
	// since that is what is suggested by the OIDC specification. Note that it may be safe to send "offline_access" even to
	// providers which do not require it, since the provider may ignore scopes that it does not understand or require (see
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.3). In the unusual case that you must avoid sending the
	// "offline_access" scope, set DoNotRequestOfflineAccess to true. This is required if your OIDC provider will reject
	// the request when it includes "offline_access" (e.g. GitLab's OIDC provider). If you need to send some other scope
	// to request a refresh token, include the scope name in the additionalScopes setting. Also note that some OIDC
	// providers may require that the "prompt" param be set to a specific value for the authorization request during an
	// OIDC Authorization Code Flow in order to receive a refresh token in the response. To adjust the prompt param, see
	// the additionalAuthorizeParameters setting.
	// +optional
	DoNotRequestOfflineAccess bool `json:"doNotRequestOfflineAccess,omitempty"`

	// AdditionalScopes are the additional scopes that will be requested from your OIDC provider in the authorization
	// request during an OIDC Authorization Code Flow and in the token request during a Resource Owner Password Credentials
	// Grant. Note that the "openid" scope will always be requested regardless of the value in this setting, since it is
	// always required according to the OIDC spec. The "offline_access" scope may also be included according to the value
	// of the DoNotRequestOfflineAccess setting. Any other scopes required should be included here in the AdditionalScopes
	// list. For example, you might like to include scopes like "profile", "email", or "groups" in order to receive the
	// related claims in the returned ID token or userinfo endpoint results if you would like to make use of those
	// claims in the OIDCClaims settings to determine the usernames and group memberships of your Kubernetes users. See
	// your OIDC provider's documentation for more information about what scopes are available to request claims.
	// +optional
	AdditionalScopes []string `json:"additionalScopes,omitempty"`

	// AdditionalAuthorizeParameters are extra query parameters that should be included in the authorize request to your
	// OIDC provider in the authorization request during an OIDC Authorization Code Flow. By default, no extra
	// parameters are sent. The standard parameters that will be sent are "response_type", "scope", "client_id",
	// "state", "nonce", "code_challenge", "code_challenge_method", and "redirect_uri". These parameters cannot be
	// included in this setting. This setting does not influence the parameters sent to the token endpoint in the
	// Resource Owner Password Credentials Grant. Starting in v0.13.0, the Pinniped Supervisor requires that your OIDC
	// provider returns refresh tokens to the Supervisor from the authorization flows. Some OIDC providers may require
	// a certain value for the "prompt" parameter in order to properly request refresh tokens. See the documentation of
	// your OIDC provider's authorization endpoint for its requirements for what to include in the request in
	// order to receive a refresh token in the response, if anything. If your provider requires the prompt parameter to
	// request a refresh token, then include it here. Also note that most providers also require a certain scope to be
	// requested in order to receive refresh tokens. See the doNotRequestOfflineAccess setting for more information about
	// using scopes to request refresh tokens.
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=name
	AdditionalAuthorizeParameters []Parameter `json:"extraAuthorizeParameters,omitempty"`

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

// Parameter is a key/value pair which represents a parameter in an HTTP request.
type Parameter struct {
	// The name of the parameter. Required.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// The value of the parameter.
	// +optional
	Value string `json:"value,omitempty"`
}

// OIDCClaims provides a mapping from upstream claims into identities.
type OIDCClaims struct {
	// Groups provides the name of the ID token claim or userinfo endpoint response claim that will be used to ascertain
	// the groups to which an identity belongs. By default, the identities will not include any group memberships when
	// this setting is not configured.
	// +optional
	Groups string `json:"groups"`

	// Username provides the name of the ID token claim or userinfo endpoint response claim that will be used to
	// ascertain an identity's username. When not set, the username will be an automatically constructed unique string
	// which will include the issuer URL of your OIDC provider along with the value of the "sub" (subject) claim from
	// the ID token.
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

// OIDCIdentityProviderSpec is the spec for configuring an OIDC identity provider.
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

// OIDCIdentityProviderList lists OIDCIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OIDCIdentityProvider `json:"items"`
}
