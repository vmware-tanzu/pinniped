// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/oidcclient/state"
)

func TestAuthorizationEndpoint(t *testing.T) {
	const (
		downstreamRedirectURI = "http://127.0.0.1/callback"
	)

	var (
		fositeInvalidClientErrorBody = here.Doc(`
		{
      "error":             "invalid_client",
      "error_verbose":     "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)",
      "error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)\n\nThe requested OAuth 2.0 Client does not exist.",
      "error_hint":        "The requested OAuth 2.0 Client does not exist.",
      "status_code":       401
    }
	`)

		fositeInvalidRedirectURIErrorBody = here.Doc(`
		{
      "error":             "invalid_request",
      "error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
      "error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nThe \"redirect_uri\" parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls.",
      "error_hint":        "The \"redirect_uri\" parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls.",
      "status_code":       400
    }
	`)

		fositeUnsupportedResponseTypeErrorQuery = url.Values{
			"error":             []string{"unsupported_response_type"},
			"error_description": []string{"The authorization server does not support obtaining a token using this method\n\nThe client is not allowed to request response_type \"unsupported\"."},
			"error_hint":        []string{`The client is not allowed to request response_type "unsupported".`},
			"state":             []string{"some-state-value"},
		}.Encode()

		fositeInvalidScopeErrorQuery = url.Values{
			"error":             []string{"invalid_scope"},
			"error_description": []string{"The requested scope is invalid, unknown, or malformed\n\nThe OAuth 2.0 Client is not allowed to request scope \"tuna\"."},
			"error_hint":        []string{`The OAuth 2.0 Client is not allowed to request scope "tuna".`},
			"state":             []string{"some-state-value"},
		}.Encode()

		fositeInvalidStateErrorQuery = url.Values{
			"error":             []string{"invalid_state"},
			"error_description": []string{"The state is missing or does not have enough characters and is therefore considered too weak\n\nRequest parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy."},
			"error_hint":        []string{`Request parameter "state" must be at least be 8 characters long to ensure sufficient entropy.`},
			"state":             []string{"short"},
		}.Encode()

		fositeMissingResponseTypeErrorQuery = url.Values{
			"error":             []string{"unsupported_response_type"},
			"error_description": []string{"The authorization server does not support obtaining a token using this method\n\nThe request is missing the \"response_type\"\" parameter."},
			"error_hint":        []string{`The request is missing the "response_type"" parameter.`},
			"state":             []string{"some-state-value"},
		}.Encode()
	)

	upstreamAuthURL, err := url.Parse("https://some-upstream-idp:8443/auth")
	require.NoError(t, err)

	upstreamOIDCIdentityProvider := provider.UpstreamOIDCIdentityProvider{
		Name:             "some-idp",
		ClientID:         "some-client-id",
		AuthorizationURL: *upstreamAuthURL,
		Scopes:           []string{"scope1", "scope2"},
	}

	issuer := "https://my-issuer.com/some-path"

	oauthStore := &storage.MemoryStore{
		Clients: map[string]fosite.Client{
			"pinniped-cli": &fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID:            "pinniped-cli",
					Public:        true,
					RedirectURIs:  []string{downstreamRedirectURI},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code"},
					Scopes:        []string{"openid", "profile", "email"},
				},
			},
		},
	}

	happyStateGenerator := func() (state.State, error) { return "test-state", nil }
	happyPKCEGenerator := func() (pkce.Code, error) { return "test-pkce", nil }
	happyNonceGenerator := func() (nonce.Nonce, error) { return "test-nonce", nil }

	// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
	// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
	expectedCodeChallenge := "VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"

	happyGetRequestPath := fmt.Sprintf(
		"/some/path?response_type=code&scope=%s&client_id=pinniped-cli&state=some-state-value&redirect_uri=%s",
		url.QueryEscape("openid profile email"),
		url.QueryEscape(downstreamRedirectURI),
	)

	type testCase struct {
		name string

		issuer        string
		idpListGetter provider.DynamicUpstreamIDPProvider
		generateState func() (state.State, error)
		generatePKCE  func() (pkce.Code, error)
		generateNonce func() (nonce.Nonce, error)
		method        string
		path          string
		contentType   string
		body          string

		wantStatus         int
		wantContentType    string
		wantBodyString     string
		wantBodyJSON       string
		wantLocationHeader string
	}

	tests := []testCase{
		{
			name:            "happy path using GET",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   happyStateGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusFound,
			wantContentType: "text/html; charset=utf-8",
			wantBodyString:  "",
			wantLocationHeader: fmt.Sprintf("%s?%s",
				upstreamAuthURL.String(),
				url.Values{
					"response_type":         []string{"code"},
					"access_type":           []string{"offline"},
					"scope":                 []string{"scope1 scope2"},
					"client_id":             []string{"some-client-id"},
					"state":                 []string{"test-state"},
					"nonce":                 []string{"test-nonce"},
					"code_challenge":        []string{expectedCodeChallenge},
					"code_challenge_method": []string{"S256"},
					"redirect_uri":          []string{issuer + "/callback/some-idp"},
				}.Encode(),
			),
		},
		{
			name:          "happy path using POST",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodPost,
			path:          "/some/path",
			contentType:   "application/x-www-form-urlencoded",
			body: url.Values{
				"response_type": []string{"code"},
				"scope":         []string{"openid profile email"},
				"client_id":     []string{"pinniped-cli"},
				"state":         []string{"some-state-value"},
				"redirect_uri":  []string{downstreamRedirectURI},
			}.Encode(),
			wantStatus:      http.StatusFound,
			wantContentType: "",
			wantBodyString:  "",
			wantLocationHeader: fmt.Sprintf("%s?%s",
				upstreamAuthURL.String(),
				url.Values{
					"response_type":         []string{"code"},
					"access_type":           []string{"offline"},
					"scope":                 []string{"scope1 scope2"},
					"client_id":             []string{"some-client-id"},
					"state":                 []string{"test-state"},
					"nonce":                 []string{"test-nonce"},
					"code_challenge":        []string{expectedCodeChallenge},
					"code_challenge_method": []string{"S256"},
					"redirect_uri":          []string{issuer + "/callback/some-idp"},
				}.Encode(),
			),
		},
		{
			name:          "downstream client does not exist",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=code&scope=%s&client_id=invalid-client&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:          "downstream redirect uri does not match what is configured for client",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=code&scope=%s&client_id=pinniped-cli&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape("http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client"),
			),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:          "response type is unsupported",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=unsupported&scope=%s&client_id=pinniped-cli&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: fmt.Sprintf("%s?%s", downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
		},
		{
			name:          "downstream scopes do not match what is configured for client",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=code&scope=%s&client_id=pinniped-cli&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email tuna"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: fmt.Sprintf("%s?%s", downstreamRedirectURI, fositeInvalidScopeErrorQuery),
		},
		{
			name:          "missing response type in request",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?scope=%s&client_id=pinniped-cli&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: fmt.Sprintf("%s?%s", downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
		},
		{
			name:          "missing client id in request",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=code&scope=%s&state=some-state-value&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:          "state does not have enough entropy",
			issuer:        issuer,
			idpListGetter: newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState: happyStateGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			method:        http.MethodGet,
			path: fmt.Sprintf(
				"/some/path?response_type=code&scope=%s&client_id=pinniped-cli&state=short&redirect_uri=%s",
				url.QueryEscape("openid profile email"),
				url.QueryEscape(downstreamRedirectURI),
			),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: fmt.Sprintf("%s?%s", downstreamRedirectURI, fositeInvalidStateErrorQuery),
		},
		{
			name:            "error while generating state",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   func() (state.State, error) { return "", fmt.Errorf("some state generator error") },
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating state param\n",
		},
		{
			name:            "error while generating nonce",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   happyStateGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   func() (nonce.Nonce, error) { return "", fmt.Errorf("some nonce generator error") },
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating nonce param\n",
		},
		{
			name:            "error while generating PKCE",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   happyStateGenerator,
			generatePKCE:    func() (pkce.Code, error) { return "", fmt.Errorf("some PKCE generator error") },
			generateNonce:   happyNonceGenerator,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating PKCE param\n",
		},
		{
			name:            "no upstream providers are configured",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(),
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: No upstream providers are configured\n",
		},
		{
			name:            "too many upstream providers are configured",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider, upstreamOIDCIdentityProvider),
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "PUT is a bad method",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			method:          http.MethodPut,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PUT (try GET or POST)\n",
		},
		{
			name:            "PATCH is a bad method",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			method:          http.MethodPatch,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PATCH (try GET or POST)\n",
		},
		{
			name:            "DELETE is a bad method",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			method:          http.MethodDelete,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: DELETE (try GET or POST)\n",
		},
	}

	runOneTestCase := func(t *testing.T, test testCase, subject http.Handler) {
		req := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		req.Header.Set("Content-Type", test.contentType)
		rsp := httptest.NewRecorder()
		subject.ServeHTTP(rsp, req)

		t.Logf("response: %#v", rsp)
		t.Logf("body: %q", rsp.Body.String())

		require.Equal(t, test.wantStatus, rsp.Code)
		requireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

		if test.wantBodyString != "" {
			require.Equal(t, test.wantBodyString, rsp.Body.String())
		}
		if test.wantBodyJSON != "" {
			require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
		}

		if test.wantLocationHeader != "" {
			actualLocation := rsp.Header().Get("Location")
			requireEqualURLs(t, actualLocation, test.wantLocationHeader)
		}
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			subject := NewHandler(test.issuer, test.idpListGetter, oauthStore, test.generateState, test.generatePKCE, test.generateNonce)
			runOneTestCase(t, test, subject)
		})
	}

	t.Run("allows upstream provider configuration to change between requests", func(t *testing.T) {
		test := tests[0]
		require.Equal(t, "happy path using GET", test.name) // re-use the happy path test case

		subject := NewHandler(test.issuer, test.idpListGetter, oauthStore, test.generateState, test.generatePKCE, test.generateNonce)

		runOneTestCase(t, test, subject)

		// Call the setter to change the upstream IDP settings.
		newProviderSettings := provider.UpstreamOIDCIdentityProvider{
			Name:             "some-other-idp",
			ClientID:         "some-other-client-id",
			AuthorizationURL: *upstreamAuthURL,
			Scopes:           []string{"other-scope1", "other-scope2"},
		}
		test.idpListGetter.SetIDPList([]provider.UpstreamOIDCIdentityProvider{newProviderSettings})

		// Update the expectations of the test case to match the new upstream IDP settings.
		test.wantLocationHeader = fmt.Sprintf("%s?%s",
			upstreamAuthURL.String(),
			url.Values{
				"response_type":         []string{"code"},
				"access_type":           []string{"offline"},
				"scope":                 []string{"other-scope1 other-scope2"},
				"client_id":             []string{"some-other-client-id"},
				"state":                 []string{"test-state"},
				"nonce":                 []string{"test-nonce"},
				"code_challenge":        []string{expectedCodeChallenge},
				"code_challenge_method": []string{"S256"},
				"redirect_uri":          []string{issuer + "/callback/some-other-idp"},
			}.Encode(),
		)

		// Run again on the same instance of the subject with the modified upstream IDP settings and the
		// modified expectations. This should ensure that the implementation is using the in-memory cache
		// of upstream IDP settings appropriately in terms of always getting the values from the cache
		// on every request.
		runOneTestCase(t, test, subject)
	})
}

func requireEqualContentType(t *testing.T, actual string, expected string) {
	t.Helper()

	if expected == "" {
		require.Empty(t, actual)
		return
	}

	actualContentType, actualContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	expectedContentType, expectedContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	require.Equal(t, actualContentType, expectedContentType)
	require.Equal(t, actualContentTypeParams, expectedContentTypeParams)
}

func requireEqualURLs(t *testing.T, actualURL string, expectedURL string) {
	t.Helper()
	actualLocationURL, err := url.Parse(actualURL)
	require.NoError(t, err)
	expectedLocationURL, err := url.Parse(expectedURL)
	require.NoError(t, err)
	require.Equal(t, expectedLocationURL.Scheme, actualLocationURL.Scheme)
	require.Equal(t, expectedLocationURL.User, actualLocationURL.User)
	require.Equal(t, expectedLocationURL.Host, actualLocationURL.Host)
	require.Equal(t, expectedLocationURL.Path, actualLocationURL.Path)
	require.Equal(t, expectedLocationURL.Query(), actualLocationURL.Query())
}

func newIDPListGetter(upstreamOIDCIdentityProviders ...provider.UpstreamOIDCIdentityProvider) provider.DynamicUpstreamIDPProvider {
	idpProvider := provider.NewDynamicUpstreamIDPProvider()
	idpProvider.SetIDPList(upstreamOIDCIdentityProviders)
	return idpProvider
}
