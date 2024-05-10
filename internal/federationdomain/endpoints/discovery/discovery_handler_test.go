// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/here"
)

func TestDiscovery(t *testing.T) {
	tests := []struct {
		name string

		issuer string
		method string
		path   string

		wantStatus      int
		wantContentType string
		wantBodyJSON    string
		wantBodyString  string
	}{
		{
			name:            "happy path",
			issuer:          "https://some-issuer.com/some/path",
			method:          http.MethodGet,
			path:            "/some/path" + oidc.WellKnownEndpointPath,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantBodyJSON: here.Doc(`
			{
				"issuer": "https://some-issuer.com/some/path",
				"authorization_endpoint": "https://some-issuer.com/some/path/oauth2/authorize",
				"token_endpoint": "https://some-issuer.com/some/path/oauth2/token",
				"jwks_uri": "https://some-issuer.com/some/path/jwks.json",
				"response_types_supported": ["code"],
				"response_modes_supported": ["query", "form_post"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["ES256"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic"],
				"scopes_supported": ["openid", "offline_access", "pinniped:request-audience", "username", "groups"],
				"code_challenge_methods_supported": ["S256"],
				"claims_supported": ["username", "groups", "additionalClaims"],
				"discovery.supervisor.pinniped.dev/v1alpha1": {
					"pinniped_identity_providers_endpoint": "https://some-issuer.com/some/path/v1alpha1/pinniped_identity_providers"
				}
			}
			`),
		},
		{
			name:            "bad method",
			issuer:          "https://some-issuer.com",
			method:          http.MethodPost,
			path:            oidc.WellKnownEndpointPath,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method not allowed (try GET)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(test.issuer)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantBodyJSON != "" {
				require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}
		})
	}
}
