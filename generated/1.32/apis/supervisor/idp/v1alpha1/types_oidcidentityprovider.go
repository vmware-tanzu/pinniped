// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
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
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// OIDCAuthorizationConfig provides information about how to form the OAuth2 authorization
// request parameters.
type OIDCAuthorizationConfig struct {
	// additionalScopes are the additional scopes that will be requested from your OIDC provider in the authorization
	// request during an OIDC Authorization Code Flow and in the token request during a Resource Owner Password Credentials
	// Grant. Note that the "openid" scope will always be requested regardless of the value in this setting, since it is
	// always required according to the OIDC spec. By default, when this field is not set, the Supervisor will request
	// the following scopes: "openid", "offline_access", "email", and "profile". See
	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims for a description of the "profile" and "email"
	// scopes. See https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess for a description of the
	// "offline_access" scope. This default value may change in future versions of Pinniped as the standard evolves,
	// or as common patterns used by providers who implement the standard in the ecosystem evolve.
	// By setting this list to anything other than an empty list, you are overriding the
	// default value, so you may wish to include some of "offline_access", "email", and "profile" in your override list.
	// If you do not want any of these scopes to be requested, you may set this list to contain only "openid".
	// Some OIDC providers may also require a scope to get access to the user's group membership, in which case you
	// may wish to include it in this list. Sometimes the scope to request the user's group membership is called
	// "groups", but unfortunately this is not specified in the OIDC standard.
	// Generally speaking, you should include any scopes required to cause the appropriate claims to be the returned by
	// your OIDC provider in the ID token or userinfo endpoint results for those claims which you would like to use in
	// the oidcClaims settings to determine the usernames and group memberships of your Kubernetes users. See
	// your OIDC provider's documentation for more information about what scopes are available to request claims.
	// Additionally, the Pinniped Supervisor requires that your OIDC provider returns refresh tokens to the Supervisor
	// from these authorization flows. For most OIDC providers, the scope required to receive refresh tokens will be
	// "offline_access". See the documentation of your OIDC provider's authorization and token endpoints for its
	// requirements for what to include in the request in order to receive a refresh token in the response, if anything.
	// Note that it may be safe to send "offline_access" even to providers which do not require it, since the provider
	// may ignore scopes that it does not understand or require (see
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.3). In the unusual case that you must avoid sending the
	// "offline_access" scope, then you must override the default value of this setting. This is required if your OIDC
	// provider will reject the request when it includes "offline_access" (e.g. GitLab's OIDC provider).
	// +optional
	AdditionalScopes []string `json:"additionalScopes,omitempty"`

	// additionalAuthorizeParameters are extra query parameters that should be included in the authorize request to your
	// OIDC provider in the authorization request during an OIDC Authorization Code Flow. By default, no extra
	// parameters are sent. The standard parameters that will be sent are "response_type", "scope", "client_id",
	// "state", "nonce", "code_challenge", "code_challenge_method", and "redirect_uri". These parameters cannot be
	// included in this setting. Additionally, the "hd" parameter cannot be included in this setting at this time.
	// The "hd" parameter is used by Google's OIDC provider to provide a hint as to which "hosted domain" the user
	// should use during login. However, Pinniped does not yet support validating the hosted domain in the resulting
	// ID token, so it is not yet safe to use this feature of Google's OIDC provider with Pinniped.
	// This setting does not influence the parameters sent to the token endpoint in the Resource Owner Password
	// Credentials Grant. The Pinniped Supervisor requires that your OIDC provider returns refresh tokens to the
	// Supervisor from the authorization flows. Some OIDC providers may require a certain value for the "prompt"
	// parameter in order to properly request refresh tokens. See the documentation of your OIDC provider's
	// authorization endpoint for its requirements for what to include in the request in order to receive a refresh
	// token in the response, if anything. If your provider requires the prompt parameter to request a refresh token,
	// then include it here. Also note that most providers also require a certain scope to be requested in order to
	// receive refresh tokens. See the additionalScopes setting for more information about using scopes to request
	// refresh tokens.
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=name
	AdditionalAuthorizeParameters []Parameter `json:"additionalAuthorizeParameters,omitempty"`

	// allowPasswordGrant, when true, will allow the use of OAuth 2.0's Resource Owner Password Credentials Grant
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
	// allowPasswordGrant defaults to false.
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

	// AdditionalClaimMappings allows for additional arbitrary upstream claim values to be mapped into the
	// "additionalClaims" claim of the ID tokens generated by the Supervisor. This should be specified as a map of
	// new claim names as the keys, and upstream claim names as the values. These new claim names will be nested
	// under the top-level "additionalClaims" claim in ID tokens generated by the Supervisor when this
	// OIDCIdentityProvider was used for user authentication. These claims will be made available to all clients.
	// This feature is not required to use the Supervisor to provide authentication for Kubernetes clusters, but can be
	// used when using the Supervisor for other authentication purposes. When this map is empty or the upstream claims
	// are not available, the "additionalClaims" claim will be excluded from the ID tokens generated by the Supervisor.
	// +optional
	AdditionalClaimMappings map[string]string `json:"additionalClaimMappings,omitempty"`
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
