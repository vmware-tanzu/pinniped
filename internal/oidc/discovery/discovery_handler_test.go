// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.pinniped.dev/internal/oidc/provider"

	"go.pinniped.dev/internal/testutil/oidctestutil"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc"
)

func TestDiscovery(t *testing.T) {
	tests := []struct {
		name string

		issuer string
		method string
		path   string

		wantStatus                 int
		wantContentType            string
		wantFirstResponseBodyJSON  interface{}
		wantSecondResponseBodyJSON interface{}
		wantBodyString             string
	}{
		{
			name:            "happy path",
			issuer:          "https://some-issuer.com/some/path",
			method:          http.MethodGet,
			path:            "/some/path" + oidc.WellKnownEndpointPath,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantFirstResponseBodyJSON: &Metadata{
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
				IDPs: []IdentityProviderMetadata{
					{Name: "a-some-ldap-idp", Type: "ldap"},
					{Name: "a-some-oidc-idp", Type: "oidc"},
					{Name: "x-some-idp", Type: "ldap"},
					{Name: "x-some-idp", Type: "oidc"},
					{Name: "z-some-ldap-idp", Type: "ldap"},
					{Name: "z-some-oidc-idp", Type: "oidc"},
				},
			},
			wantSecondResponseBodyJSON: &Metadata{
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
				IDPs: []IdentityProviderMetadata{
					{Name: "some-other-ldap-idp-1", Type: "ldap"},
					{Name: "some-other-ldap-idp-2", Type: "ldap"},
					{Name: "some-other-oidc-idp-1", Type: "oidc"},
					{Name: "some-other-oidc-idp-2", Type: "oidc"},
				},
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
			idpLister := oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "z-some-oidc-idp"}).
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "x-some-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "a-some-ldap-idp"}).
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "a-some-oidc-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "z-some-ldap-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "x-some-idp"}).
				Build()

			handler := NewHandler(test.issuer, idpLister)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantFirstResponseBodyJSON != nil {
				wantJSON, err := json.Marshal(test.wantFirstResponseBodyJSON)
				require.NoError(t, err)
				require.JSONEq(t, string(wantJSON), rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}

			// Change the list of IDPs in the cache.
			idpLister.SetLDAPIdentityProviders([]provider.UpstreamLDAPIdentityProviderI{
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ldap-idp-1"},
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ldap-idp-2"},
			})
			idpLister.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{
				&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "some-other-oidc-idp-1"},
				&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "some-other-oidc-idp-2"},
			})

			// Make the same request to the same handler instance again, and expect different results.
			rsp = httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantFirstResponseBodyJSON != nil {
				wantJSON, err := json.Marshal(test.wantSecondResponseBodyJSON)
				require.NoError(t, err)
				require.JSONEq(t, string(wantJSON), rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}
		})
	}
}
