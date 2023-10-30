// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package chooseidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/endpoints/chooseidp/chooseidphtml"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestChooseIDPHandler(t *testing.T) {
	const testIssuer = "https://pinniped.dev/issuer"

	testReqQuery := url.Values{
		"client_id":     []string{"foo"},
		"redirect_uri":  []string{"bar"},
		"scope":         []string{"baz"},
		"response_type": []string{"bat"},
	}
	testIssuerWithTestReqQuery := testIssuer + "?" + testReqQuery.Encode()

	tests := []struct {
		name string

		method    string
		reqTarget string
		idps      federationdomainproviders.FederationDomainIdentityProvidersListerI

		wantStatus      int
		wantContentType string
		wantBodyString  string
	}{
		{
			name:      "happy path",
			method:    http.MethodGet,
			reqTarget: "/some/path" + oidc.ChooseIDPEndpointPath + "?" + testReqQuery.Encode(),
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("oidc2").Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("ldap1").Build()).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("z-ad1").Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("ldap2").Build()).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("oidc1").Build()).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName("ad2").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantBodyString: testutil.ExpectedChooseIDPPageHTML(chooseidphtml.CSS(), chooseidphtml.JS(), []testutil.ChooseIDPPageExpectedValue{
				// Should be sorted alphabetically by displayName.
				{DisplayName: "ad2", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=ad2"},
				{DisplayName: "ldap1", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=ldap1"},
				{DisplayName: "ldap2", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=ldap2"},
				{DisplayName: "oidc1", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=oidc1"},
				{DisplayName: "oidc2", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=oidc2"},
				{DisplayName: "z-ad1", URL: testIssuerWithTestReqQuery + "&pinniped_idp_name=z-ad1"},
			}),
		},
		{
			name:      "happy path when there are special characters in the IDP name",
			method:    http.MethodGet,
			reqTarget: "/some/path" + oidc.ChooseIDPEndpointPath + "?" + testReqQuery.Encode(),
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName(`This is Ryan's IDP 👍\~!@#$%^&*()-+[]{}\|;'"<>,.?`).Build()).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().WithName(`This is Josh's IDP 🦭`).Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantBodyString: testutil.ExpectedChooseIDPPageHTML(chooseidphtml.CSS(), chooseidphtml.JS(), []testutil.ChooseIDPPageExpectedValue{
				// Should be sorted alphabetically by displayName.
				{
					DisplayName: `This is Josh's IDP 🦭`,
					URL:         testIssuerWithTestReqQuery + `&pinniped_idp_name=` + url.QueryEscape(`This is Josh's IDP 🦭`),
				},
				{
					DisplayName: `This is Ryan's IDP 👍\~!@#$%^&*()-+[]{}\|;'"<>,.?`,
					URL:         testIssuerWithTestReqQuery + `&pinniped_idp_name=` + url.QueryEscape(`This is Ryan's IDP 👍\~!@#$%^&*()-+[]{}\|;'"<>,.?`),
				},
			}),
		},
		{
			name:      "no valid IDPs are configured on the FederationDomain",
			method:    http.MethodGet,
			reqTarget: "/some/path" + oidc.ChooseIDPEndpointPath + "?" + testReqQuery.Encode(),
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: please check the server's configuration: no valid identity providers found for this FederationDomain\n",
		},
		{
			name:      "no query params on the request",
			method:    http.MethodGet,
			reqTarget: "/some/path" + oidc.ChooseIDPEndpointPath,
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("x-some-idp").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Bad Request: missing required query params (must include client_id, redirect_uri, scope, and response_type)\n",
		},
		{
			name:      "missing required query param(s) on the request",
			method:    http.MethodGet,
			reqTarget: "/some/path" + oidc.ChooseIDPEndpointPath + "?client_id=foo",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("x-some-idp").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Bad Request: missing required query params (must include client_id, redirect_uri, scope, and response_type)\n",
		},
		{
			name:      "bad request method",
			method:    http.MethodPost,
			reqTarget: oidc.ChooseIDPEndpointPath,
			idps: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().WithName("x-some-idp").Build()).
				BuildFederationDomainIdentityProvidersListerFinder(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: POST (try GET)\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler := NewHandler(testIssuer, test.idps)

			req := httptest.NewRequest(test.method, test.reqTarget, nil)
			rsp := httptest.NewRecorder()
			handler.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)
			require.Equal(t, test.wantContentType, rsp.Header().Get("Content-Type"))
			require.Equal(t, test.wantBodyString, rsp.Body.String())
			testutil.RequireSecurityHeadersWithIDPChooserPageCSPs(t, rsp)
		})
	}
}
