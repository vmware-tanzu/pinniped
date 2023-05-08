// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idpdiscovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestIDPDiscovery(t *testing.T) {
	tests := []struct {
		name string

		method string
		path   string

		wantStatus                 int
		wantContentType            string
		wantFirstResponseBodyJSON  string
		wantSecondResponseBodyJSON string
		wantBodyString             string
	}{
		{
			name:            "happy path",
			method:          http.MethodGet,
			path:            "/some/path" + oidc.WellKnownEndpointPath,
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantFirstResponseBodyJSON: here.Doc(`{
				"pinniped_identity_providers": [
					{"name": "a-some-ldap-idp", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "a-some-oidc-idp", "type": "oidc",            "flows": ["browser_authcode"]},
					{"name": "x-some-idp",      "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "x-some-idp",      "type": "oidc",            "flows": ["browser_authcode"]},
					{"name": "y-some-ad-idp",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-ad-idp",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-ldap-idp", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-oidc-idp", "type": "oidc",            "flows": ["browser_authcode", "cli_password"]}
				]
			}`),
			wantSecondResponseBodyJSON: here.Doc(`{
				"pinniped_identity_providers": [
					{"name": "some-other-ad-idp-1",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ad-idp-2",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ldap-idp-1", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ldap-idp-2", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-oidc-idp-1", "type": "oidc",            "flows": ["browser_authcode", "cli_password"]},
					{"name": "some-other-oidc-idp-2", "type": "oidc",            "flows": ["browser_authcode"]}
				]
			}`),
		},
		{
			name:            "bad method",
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
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "z-some-oidc-idp", AllowPasswordGrant: true}).
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "x-some-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "a-some-ldap-idp"}).
				WithOIDC(&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "a-some-oidc-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "z-some-ldap-idp"}).
				WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "x-some-idp"}).
				WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "z-some-ad-idp"}).
				WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "y-some-ad-idp"}).
				Build()

			handler := NewHandler(idpLister)
			req := httptest.NewRequest(test.method, test.path, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantFirstResponseBodyJSON != "" {
				require.JSONEq(t, test.wantFirstResponseBodyJSON, rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}

			// Change the list of IDPs in the cache.
			idpLister.SetLDAPIdentityProviders([]upstreamprovider.UpstreamLDAPIdentityProviderI{
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ldap-idp-1"},
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ldap-idp-2"},
			})
			idpLister.SetOIDCIdentityProviders([]upstreamprovider.UpstreamOIDCIdentityProviderI{
				&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "some-other-oidc-idp-1", AllowPasswordGrant: true},
				&oidctestutil.TestUpstreamOIDCIdentityProvider{Name: "some-other-oidc-idp-2"},
			})

			idpLister.SetActiveDirectoryIdentityProviders([]upstreamprovider.UpstreamLDAPIdentityProviderI{
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ad-idp-2"},
				&oidctestutil.TestUpstreamLDAPIdentityProvider{Name: "some-other-ad-idp-1"},
			})

			// Make the same request to the same handler instance again, and expect different results.
			rsp = httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))

			if test.wantFirstResponseBodyJSON != "" {
				require.JSONEq(t, test.wantSecondResponseBodyJSON, rsp.Body.String())
			}

			if test.wantBodyString != "" {
				require.Equal(t, test.wantBodyString, rsp.Body.String())
			}
		})
	}
}
