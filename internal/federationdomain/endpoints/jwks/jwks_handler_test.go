// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

func TestJWKSEndpoint(t *testing.T) {
	testJWKSJSONString := here.Doc(`
		{
		  "keys": [
			{
			  "use": "sig",
			  "kty": "EC",
			  "kid": "pinniped-supervisor-key",
			  "crv": "P-256",
			  "alg": "ES256",
			  "x": "awmmj6CIMhSoJyfsqH7sekbTeY72GGPLEy16tPWVz2U",
			  "y": "FcMh06uXLaq9b2MOixlLVidUkycO1u7IHOkrTi7N0aw"
			}
		  ]
		}
	`)

	tests := []struct {
		name string

		issuer   string
		provider DynamicJWKSProvider
		method   string
		path     string

		wantStatus         int
		wantContentType    string
		wantBodyJSONString string
		wantBodyString     string
	}{
		{
			name:               "happy path",
			issuer:             "https://some-issuer.com/some/path",
			provider:           newDynamicJWKSProvider(t, "https://some-issuer.com/some/path", testJWKSJSONString),
			method:             http.MethodGet,
			path:               "/some/path",
			wantStatus:         http.StatusOK,
			wantContentType:    "application/json",
			wantBodyJSONString: testJWKSJSONString,
		},
		{
			name:            "bad method",
			issuer:          "https://some-issuer.com",
			provider:        newDynamicJWKSProvider(t, "https://some-issuer.com", testJWKSJSONString),
			method:          http.MethodPost,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method not allowed (try GET)\n",
		},
		{
			name:            "no JWKS found in provider's cache for this issuer",
			issuer:          "https://some-issuer.com",
			provider:        newDynamicJWKSProvider(t, "https://some-other-unrelated-issuer.com", testJWKSJSONString),
			method:          http.MethodGet,
			path:            "/some/path",
			wantStatus:      http.StatusNotFound,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "JWKS not found for requested issuer\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(test.issuer, test.provider)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantBodyJSONString != "" {
				require.JSONEq(t, test.wantBodyJSONString, rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}
		})
	}
}

func newDynamicJWKSProvider(t *testing.T, issuer string, jwksJSON string) DynamicJWKSProvider {
	t.Helper()
	jwksProvider := NewDynamicJWKSProvider()
	var keySet jose.JSONWebKeySet
	err := json.Unmarshal([]byte(jwksJSON), &keySet)
	require.NoError(t, err)
	issuerToJWKSMap := map[string]*jose.JSONWebKeySet{
		issuer: &keySet,
	}
	issuerToActiveJWKMap := map[string]*jose.JSONWebKey{
		issuer: &keySet.Keys[0],
	}
	jwksProvider.SetIssuerToJWKSMap(issuerToJWKSMap, issuerToActiveJWKMap)
	return jwksProvider
}
