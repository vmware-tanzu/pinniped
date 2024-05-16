// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idpdiscovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
)

func TestIDPDiscovery(t *testing.T) {
	tests := []struct {
		name string

		method    string
		path      string
		idpLister *testidplister.TestFederationDomainIdentityProvidersListerFinder

		wantStatus                 int
		wantContentType            string
		wantFirstResponseBodyJSON  string
		wantSecondResponseBodyJSON string
		wantBodyString             string
	}{
		{
			name:   "happy path",
			method: http.MethodGet,
			path:   "/some/path" + oidc.WellKnownEndpointPath,
			idpLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("z-some-oidc-idp").WithAllowPasswordGrant(true).Build()).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("x-some-oidc-idp").Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("a-some-ldap-idp").Build()).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("a-some-oidc-idp").Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("z-some-ldap-idp").Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("x-some-ldap-idp").Build()).
				WithGitHub(oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().WithName("g-some-github-idp").Build()).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("z-some-ad-idp").Build()).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("y-some-ad-idp").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantFirstResponseBodyJSON: here.Doc(`{
				"pinniped_identity_providers": [
					{"name": "a-some-ldap-idp", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "a-some-oidc-idp", "type": "oidc",            "flows": ["browser_authcode"]},
					{"name": "g-some-github-idp", "type": "github",        "flows": ["browser_authcode"]},
					{"name": "x-some-ldap-idp", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "x-some-oidc-idp", "type": "oidc",            "flows": ["browser_authcode"]},
					{"name": "y-some-ad-idp",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-ad-idp",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-ldap-idp", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "z-some-oidc-idp", "type": "oidc",            "flows": ["browser_authcode", "cli_password"]}
				],
				"pinniped_supported_identity_provider_types": [
					{"type": "activedirectory"},
					{"type": "github"},
					{"type": "ldap"},
					{"type": "oidc"}
				]
			}`),
			wantSecondResponseBodyJSON: here.Doc(`{
				"pinniped_identity_providers": [
					{"name": "g-some-github-idp",     "type": "github",          "flows": ["browser_authcode"]},
					{"name": "some-other-ad-idp-1",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ad-idp-2",   "type": "activedirectory", "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ldap-idp-1", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-ldap-idp-2", "type": "ldap",            "flows": ["cli_password", "browser_authcode"]},
					{"name": "some-other-oidc-idp-1", "type": "oidc",            "flows": ["browser_authcode", "cli_password"]},
					{"name": "some-other-oidc-idp-2", "type": "oidc",            "flows": ["browser_authcode"]}
				],
				"pinniped_supported_identity_provider_types": [
					{"type": "activedirectory"},
					{"type": "github"},
					{"type": "ldap"},
					{"type": "oidc"}
				]
			}`),
		},
		{
			name:   "no starting IDPs still returns supported IDP types",
			method: http.MethodGet,
			path:   "/some/path" + oidc.WellKnownEndpointPath,
			idpLister: testidplister.NewUpstreamIDPListerBuilder().
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusOK,
			wantContentType: "application/json",
			wantFirstResponseBodyJSON: here.Doc(`{
				"pinniped_identity_providers": [],
				"pinniped_supported_identity_provider_types": [
					{"type": "activedirectory"},
					{"type": "github"},
					{"type": "ldap"},
					{"type": "oidc"}
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
				],
				"pinniped_supported_identity_provider_types": [
					{"type": "activedirectory"},
					{"type": "github"},
					{"type": "ldap"},
					{"type": "oidc"}
				]
			}`),
		},
		{
			name:   "bad method",
			method: http.MethodPost,
			path:   oidc.WellKnownEndpointPath,
			idpLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("some-oidc-idp").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method not allowed (try GET)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotNil(t, test.idpLister)
			handler := NewHandler(test.idpLister)
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
			test.idpLister.SetLDAPIdentityProviders([]*oidctestutil.TestUpstreamLDAPIdentityProvider{
				oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("some-other-ldap-idp-1").Build(),
				oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("some-other-ldap-idp-2").Build(),
			})
			test.idpLister.SetOIDCIdentityProviders([]*oidctestutil.TestUpstreamOIDCIdentityProvider{
				oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("some-other-oidc-idp-1").WithAllowPasswordGrant(true).Build(),
				oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("some-other-oidc-idp-2").Build(),
			})
			test.idpLister.SetActiveDirectoryIdentityProviders([]*oidctestutil.TestUpstreamLDAPIdentityProvider{
				oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("some-other-ad-idp-2").Build(),
				oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("some-other-ad-idp-1").Build(),
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
