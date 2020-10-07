// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package discovery provides a handler for the OIDC discovery endpoint.
package discovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"go.pinniped.dev/internal/oidc"
)

// Metadata holds all fields (that we care about) from the OpenID Provider Metadata section in the
// OpenID Connect Discovery specification:
// https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3.
type Metadata struct {
	// vvvRequiredvvv

	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ^^^Required^^^

	// vvvOptionalvvv

	TokenEndpointAuthMethodsSupported           []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgoValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                             []string `json:"scopes_supported"`
	ClaimsSupported                             []string `json:"claims_supported"`

	// ^^^Optional^^^
}

// IssuerGetter holds onto an issuer which can be retrieved via its GetIssuer function. If there is
// no valid issuer, then nil will be returned.
//
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type IssuerGetter interface {
	GetIssuer() *url.URL
}

// New returns an http.Handler that will use information from the provided IssuerGetter to serve an
// OIDC discovery endpoint.
func New(ig IssuerGetter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		issuer := ig.GetIssuer()
		if issuer == nil || r.URL.Path != issuer.Path+oidc.WellKnownURLPath {
			http.Error(w, `{"error": "OIDC discovery not available (unknown issuer)"}`, http.StatusNotFound)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, `{"error": "Method not allowed (try GET)"}`, http.StatusMethodNotAllowed)
			return
		}

		issuerURL := issuer.String()
		oidcConfig := Metadata{
			Issuer:                            issuerURL,
			AuthorizationEndpoint:             fmt.Sprintf("%s/oauth2/v0/auth", issuerURL),
			TokenEndpoint:                     fmt.Sprintf("%s/oauth2/v0/token", issuerURL),
			JWKSURI:                           fmt.Sprintf("%s/jwks.json", issuerURL),
			ResponseTypesSupported:            []string{"code"},
			SubjectTypesSupported:             []string{"public"},
			IDTokenSigningAlgValuesSupported:  []string{"RS256"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			TokenEndpointAuthSigningAlgoValuesSupported: []string{"RS256"},
			ScopesSupported: []string{"openid", "offline"},
			ClaimsSupported: []string{"groups"},
		}
		if err := json.NewEncoder(w).Encode(&oidcConfig); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}
