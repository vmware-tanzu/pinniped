// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Status of an OIDC identity provider.
type OpenIDConnectIdentityProviderStatus struct {
	// Represents the observations of an identity provider's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// OpenIDConnectAuthorizationConfig provides information about how to form the OAuth2 authorization
// request parameters.
type OpenIDConnectAuthorizationConfig struct {
	// RedirectURI is the URI of the redirect endpoint that will be used in the OAuth2 authorization
	// request flow with an OIDC identity provider.
	// +kubebuilder:validation:Pattern=`^https?://`
	RedirectURI string `json:"redirectURI"`

	// Scopes are the scopes that will be requested as part of the authorization request flow with
	// an OIDC identity provider.
	Scopes []string `json:"scopes"`
}

// OpenIDConnectClaims provides a mapping from upstream claims into identities.
type OpenIDConnectClaims struct {
	// Groups provides the name of the token claim that will be used to ascertain the groups to which
	// an identity belongs.
	Groups string `json:"groups"`

	// Username provides the name of the token claim that will be used to ascertain an identity's
	// username.
	Username string `json:"username"`
}

// OpenIDConnectClient contains information about an OIDC client (e.g., client ID and client
// secret).
type OpenIDConnectClient struct {
	// SecretName contains the name of a namespace-local Secret object that provides the clientID and
	// clientSecret for an OIDC client. If only the SecretName is specified in an OpenIDConnectClient
	// struct, then it is expected that the Secret is of type "secrets.pinniped.dev/oidc" with keys
	// "clientID" and "clientSecret".
	SecretName string `json:"secretName"`
}

// Spec for configuring an OIDC identity provider.
type OpenIDConnectIdentityProviderSpec struct {
	// Issuer is the issuer URL of this OIDC identity provider, i.e., where to fetch
	// /.well-known/openid-configuration.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Issuer string `json:"issuer"`

	// AuthorizationConfig holds information about how to form the OAuth2 authorization request
	// parameters to be used with this OIDC identity provider.
	AuthorizationConfig OpenIDConnectAuthorizationConfig `json:"authorizationConfig"`

	// Claims provides the names of token claims that will be used when inspecting an identity from
	// this OIDC identity provider.
	Claims OpenIDConnectClaims `json:"claims"`

	// OpenIDConnectClient contains OIDC client information to be used used with this OIDC identity
	// provider.
	Client OpenIDConnectClient `json:"client"`
}

// OpenIDConnectIdentityProvider describes the configuration of a Pinniped OIDC identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=all;idp;idps,shortName=openidconnectidp;openidconnectidps
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
type OpenIDConnectIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec OpenIDConnectIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status OpenIDConnectIdentityProviderStatus `json:"status,omitempty"`
}

// List of OpenIDConnectIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenIDConnectIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OpenIDConnectIdentityProvider `json:"items"`
}
