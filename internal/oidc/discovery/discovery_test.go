// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc/issuerprovider"
)

func TestDiscovery(t *testing.T) {
	tests := []struct {
		name string

		issuer string
		method string

		wantStatus      int
		wantContentType string
		wantBody        interface{}
	}{
		{
			name:       "issuer returns nil issuer",
			method:     http.MethodGet,
			wantStatus: http.StatusServiceUnavailable,
			wantBody: map[string]string{
				"error": "OIDC discovery not available (unknown issuer)",
			},
		},
		{
			name:            "issuer returns non-nil issuer",
			issuer:          "https://some-issuer.com",
			method:          http.MethodGet,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantBody: &Metadata{
				Issuer:                           "https://some-issuer.com",
				AuthorizationEndpoint:            "https://some-issuer.com/oauth2/v0/auth",
				TokenEndpoint:                    "https://some-issuer.com/oauth2/v0/token",
				JWKSURL:                          "https://some-issuer.com/oauth2/v0/keys",
				ResponseTypesSupported:           []string{},
				SubjectTypesSupported:            []string{},
				IDTokenSigningAlgValuesSupported: []string{},
			},
		},
		{
			name:       "bad method",
			issuer:     "https://some-issuer.com",
			method:     http.MethodPost,
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
			if test.issuer != "" {
				p.SetIssuer(&test.issuer)
			} else {
				p.SetIssuer(nil)
			}

			handler := New(p)
			req := httptest.NewRequest(test.method, "/this/path/shouldnt/matter", nil)
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
