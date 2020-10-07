// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/issuerprovider"
)

func TestDiscovery(t *testing.T) {
	tests := []struct {
		name string

		issuer *url.URL
		method string
		path   string

		wantStatus      int
		wantContentType string
		wantBody        interface{}
	}{
		{
			name:       "nil issuer",
			method:     http.MethodGet,
			path:       oidc.WellKnownURLPath,
			wantStatus: http.StatusNotFound,
			wantBody: map[string]string{
				"error": "OIDC discovery not available (unknown issuer)",
			},
		},
		{
			name:       "root path mismatch",
			issuer:     must(url.Parse("https://some-issuer.com/some/path")),
			method:     http.MethodGet,
			path:       "/some/other/path" + oidc.WellKnownURLPath,
			wantStatus: http.StatusNotFound,
			wantBody: map[string]string{
				"error": "OIDC discovery not available (unknown issuer)",
			},
		},
		{
			name:       "well-known path mismatch",
			issuer:     must(url.Parse("https://some-issuer.com/some/path")),
			method:     http.MethodGet,
			path:       "/some/path/that/is/not/the/well-known/path",
			wantStatus: http.StatusNotFound,
			wantBody: map[string]string{
				"error": "OIDC discovery not available (unknown issuer)",
			},
		},
		{
			name:            "issuer path matches",
			issuer:          must(url.Parse("https://some-issuer.com/some/path")),
			method:          http.MethodGet,
			path:            "/some/path" + oidc.WellKnownURLPath,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantBody: &Metadata{
				Issuer:                            "https://some-issuer.com/some/path",
				AuthorizationEndpoint:             "https://some-issuer.com/some/path/oauth2/v0/auth",
				TokenEndpoint:                     "https://some-issuer.com/some/path/oauth2/v0/token",
				JWKSURI:                           "https://some-issuer.com/some/path/jwks.json",
				ResponseTypesSupported:            []string{"code"},
				SubjectTypesSupported:             []string{"public"},
				IDTokenSigningAlgValuesSupported:  []string{"RS256"},
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
				TokenEndpointAuthSigningAlgoValuesSupported: []string{"RS256"},
				ScopesSupported: []string{"openid", "offline"},
				ClaimsSupported: []string{"groups"},
			},
		},
		{
			name:       "bad method",
			issuer:     must(url.Parse("https://some-issuer.com")),
			method:     http.MethodPost,
			path:       oidc.WellKnownURLPath,
			wantStatus: http.StatusMethodNotAllowed,
			wantBody: map[string]string{
				"error": "Method not allowed (try GET)",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			p := issuerprovider.New()
			err := p.SetIssuer(test.issuer)
			require.NoError(t, err)

			handler := New(p)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			if test.wantContentType != "" {
				require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))
			}

			if test.wantBody != nil {
				wantJSON, err := json.Marshal(test.wantBody)
				require.NoError(t, err)
				require.JSONEq(t, string(wantJSON), rsp.Body.String())
			}
		})
	}
}

func must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	return u
}
