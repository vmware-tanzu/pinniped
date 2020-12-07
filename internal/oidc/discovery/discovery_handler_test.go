// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc"
)

func TestDiscovery(t *testing.T) {
	tests := []struct {
		name string

		issuer string
		method string
		path   string

		wantStatus      int
		wantContentType string
		wantBodyJSON    interface{}
		wantBodyString  string
	}{
		{
			name:            "happy path",
			issuer:          "https://some-issuer.com/some/path",
			method:          http.MethodGet,
			path:            "/some/path" + oidc.WellKnownEndpointPath,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantBodyJSON: &Metadata{
				Issuer:                            "https://some-issuer.com/some/path",
				AuthorizationEndpoint:             "https://some-issuer.com/some/path/oauth2/authorize",
				TokenEndpoint:                     "https://some-issuer.com/some/path/oauth2/token",
				JWKSURI:                           "https://some-issuer.com/some/path/jwks.json",
				ResponseTypesSupported:            []string{"code"},
				SubjectTypesSupported:             []string{"public"},
				IDTokenSigningAlgValuesSupported:  []string{"ES256"},
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
				ScopesSupported:                   []string{"openid", "offline"},
				ClaimsSupported:                   []string{"groups"},
			},
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
		test := test
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(test.issuer)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantBodyJSON != nil {
				wantJSON, err := json.Marshal(test.wantBodyJSON)
				require.NoError(t, err)
				require.JSONEq(t, string(wantJSON), rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}
		})
	}
}
