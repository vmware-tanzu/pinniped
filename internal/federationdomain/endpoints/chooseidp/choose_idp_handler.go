// Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package chooseidp

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/endpoints/chooseidp/chooseidphtml"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
)

// NewHandler returns a http.Handler that serves an IDP chooser web page. The authorization endpoint may redirect
// to this page, copying all the same parameters from the original authorization request. Each button on this page
// simply adds the IDP's name as an additional request parameter to the original authorization request's parameters,
// and sends the user back to the authorization endpoint, where the authorization flow can start from scratch using
// the original params with the extra pinniped_idp_name param added.
func NewHandler(authURL string, upstreamIDPs federationdomainproviders.FederationDomainIdentityProvidersListerI) http.Handler {
	handler := httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet {
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
		}

		// This is just a sanity check that it appears to be an authorize request.
		// Actual enforcement of parameters will happen at the authorization endpoint.
		query := r.URL.Query()
		//nolint:staticcheck // De Morgan's doesn't make this more readable
		if !(query.Has("client_id") && query.Has("redirect_uri") && query.Has("scope") && query.Has("response_type")) {
			return httperr.New(http.StatusBadRequest, "missing required query params (must include client_id, redirect_uri, scope, and response_type)")
		}

		newIDPForPageData := func(displayName string) chooseidphtml.IdentityProvider {
			return chooseidphtml.IdentityProvider{
				DisplayName: displayName,
				URL: fmt.Sprintf("%s?%s&%s=%s",
					authURL, r.URL.Query().Encode(), oidc.AuthorizeUpstreamIDPNameParamName, url.QueryEscape(displayName)),
			}
		}

		var idps []chooseidphtml.IdentityProvider
		for _, p := range upstreamIDPs.GetIdentityProviders() {
			idps = append(idps, newIDPForPageData(p.GetDisplayName()))
		}

		sort.SliceStable(idps, func(i, j int) bool {
			return idps[i].DisplayName < idps[j].DisplayName
		})

		if len(idps) == 0 {
			// This shouldn't normally happen in practice because the auth endpoint would not have redirected to here.
			return httperr.New(http.StatusInternalServerError,
				"please check the server's configuration: no valid identity providers found for this FederationDomain")
		}

		return chooseidphtml.Template().Execute(w, &chooseidphtml.PageData{IdentityProviders: idps})
	})

	return wrapSecurityHeaders(handler)
}

func wrapSecurityHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := securityheader.WrapWithCustomCSP(handler, chooseidphtml.ContentSecurityPolicy())
		wrapped.ServeHTTP(w, r)
	})
}
