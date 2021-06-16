// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package discovery provides a handler for the OIDC discovery endpoint.
package discovery

import (
	"bytes"
	"encoding/json"
	"net/http"

	"go.pinniped.dev/internal/oidc"
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
	ResponseModesSupported           []string `json:"response_modes_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// ^^^ Required ^^^

	// vvv Optional vvv

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`

	// ^^^ Optional ^^^

	// vvv Custom vvv

	SupervisorDiscovery SupervisorDiscoveryMetadataV1Alpha1 `json:"discovery.supervisor.pinniped.dev/v1alpha1"`

	// ^^^ Custom ^^^
}

type SupervisorDiscoveryMetadataV1Alpha1 struct {
	PinnipedIDPsEndpoint string `json:"pinniped_identity_providers_endpoint"`
}

type IdentityProviderMetadata struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// NewHandler returns an http.Handler that serves an OIDC discovery endpoint.
func NewHandler(issuerURL string) http.Handler {
	oidcConfig := Metadata{
		Issuer:                            issuerURL,
		AuthorizationEndpoint:             issuerURL + oidc.AuthorizationEndpointPath,
		TokenEndpoint:                     issuerURL + oidc.TokenEndpointPath,
		JWKSURI:                           issuerURL + oidc.JWKSEndpointPath,
		SupervisorDiscovery:               SupervisorDiscoveryMetadataV1Alpha1{PinnipedIDPsEndpoint: issuerURL + oidc.PinnipedIDPsPathV1Alpha1},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query", "form_post"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		ScopesSupported:                   []string{"openid", "offline"},
		ClaimsSupported:                   []string{"groups"},
	}

	var b bytes.Buffer
	encodeErr := json.NewEncoder(&b).Encode(&oidcConfig)
	encodedMetadata := b.Bytes()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `Method not allowed (try GET)`, http.StatusMethodNotAllowed)
			return
		}

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
