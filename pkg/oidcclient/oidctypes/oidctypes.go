// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidctypes provides core data types for OIDC token structures.
package oidctypes

import v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AccessToken is an OAuth2 access token.
type AccessToken struct {
	// Token is the token that authorizes and authenticates the requests.
	Token string `json:"token"`

	// Type is the type of token.
	Type string `json:"type,omitempty"`

	// Expiry is the optional expiration time of the access token.
	Expiry v1.Time `json:"expiryTimestamp,omitempty"`
}

// RefreshToken is an OAuth2 refresh token.
type RefreshToken struct {
	// Token is a token that's used by the application (as opposed to the user) to refresh the access token if it expires.
	Token string `json:"token"`
}

// IDToken is an OpenID Connect ID token.
type IDToken struct {
	// Token is an OpenID Connect ID token.
	Token string `json:"token"`

	// Expiry is the optional expiration time of the ID token.
	Expiry v1.Time `json:"expiryTimestamp,omitempty"`

	// Claims are the claims expressed by the Token.
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// Token contains the elements of an OIDC session.
type Token struct {
	// AccessToken is the token that authorizes and authenticates the requests.
	AccessToken *AccessToken `json:"access,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken *RefreshToken `json:"refresh,omitempty"`

	// IDToken is an OpenID Connect ID token.
	IDToken *IDToken `json:"id,omitempty"`
}
