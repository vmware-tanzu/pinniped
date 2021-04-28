// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package discovery provides a handler for the OIDC discovery endpoint.
package discovery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"

	"go.pinniped.dev/internal/oidc"
)

const (
	idpDiscoveryTypeLDAP = "ldap"
	idpDiscoveryTypeOIDC = "oidc"
)

// Metadata holds all fields (that we care about) from the OpenID Provider Metadata section in the
// OpenID Connect Discovery specification:
// https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3.
type Metadata struct {
	// vvv Required vvv

	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ^^^ Required ^^^

	// vvv Optional vvv

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`

	// ^^^ Optional ^^^

	// vvv Custom vvv

	IDPs []IdentityProviderMetadata `json:"pinniped_idps"`

	// ^^^ Custom ^^^
}

type IdentityProviderMetadata struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// NewHandler returns an http.Handler that serves an OIDC discovery endpoint.
func NewHandler(issuerURL string, upstreamIDPs oidc.UpstreamIdentityProvidersLister) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `Method not allowed (try GET)`, http.StatusMethodNotAllowed)
			return
		}

		encodedMetadata, encodeErr := metadata(issuerURL, upstreamIDPs)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(encodedMetadata); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func metadata(issuerURL string, upstreamIDPs oidc.UpstreamIdentityProvidersLister) ([]byte, error) {
	oidcConfig := Metadata{
		Issuer:                            issuerURL,
		AuthorizationEndpoint:             issuerURL + oidc.AuthorizationEndpointPath,
		TokenEndpoint:                     issuerURL + oidc.TokenEndpointPath,
		JWKSURI:                           issuerURL + oidc.JWKSEndpointPath,
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		ScopesSupported:                   []string{"openid", "offline"},
		ClaimsSupported:                   []string{"groups"},
		IDPs:                              []IdentityProviderMetadata{},
	}

	// The cache of IDPs could change at any time, so always recalculate the list.
	for _, provider := range upstreamIDPs.GetLDAPIdentityProviders() {
		oidcConfig.IDPs = append(oidcConfig.IDPs, IdentityProviderMetadata{Name: provider.GetName(), Type: idpDiscoveryTypeLDAP})
	}
	for _, provider := range upstreamIDPs.GetOIDCIdentityProviders() {
		oidcConfig.IDPs = append(oidcConfig.IDPs, IdentityProviderMetadata{Name: provider.GetName(), Type: idpDiscoveryTypeOIDC})
	}

	// Nobody like an API that changes the results unnecessarily. :)
	sort.SliceStable(oidcConfig.IDPs, func(i, j int) bool {
		return oidcConfig.IDPs[i].Name < oidcConfig.IDPs[j].Name
	})

	var b bytes.Buffer
	encodeErr := json.NewEncoder(&b).Encode(&oidcConfig)
	encodedMetadata := b.Bytes()

	return encodedMetadata, encodeErr
}
