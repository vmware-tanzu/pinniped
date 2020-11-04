// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"html"
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

		fositeMissingCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nThis client must include a code_challenge when performing the authorize code flow, but it is missing.",
			"error_hint":        "This client must include a code_challenge when performing the authorize code flow, but it is missing.",
			"state":             "some-state-value",
		}

		fositeMissingCodeChallengeMethodErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nClients must use code_challenge_method=S256, plain is not allowed.",
			"error_hint":        "Clients must use code_challenge_method=S256, plain is not allowed.",
			"state":             "some-state-value",
		}

		fositeInvalidCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nThe code_challenge_method is not supported, use S256 instead.",
			"error_hint":        "The code_challenge_method is not supported, use S256 instead.",
			"state":             "some-state-value",
		}

		fositeUnsupportedResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method\n\nThe client is not allowed to request response_type \"unsupported\".",
			"error_hint":        `The client is not allowed to request response_type "unsupported".`,
			"state":             "some-state-value",
		}

		fositeInvalidScopeErrorQuery = map[string]string{
			"error":             "invalid_scope",
			"error_description": "The requested scope is invalid, unknown, or malformed\n\nThe OAuth 2.0 Client is not allowed to request scope \"tuna\".",
			"error_hint":        `The OAuth 2.0 Client is not allowed to request scope "tuna".`,
			"state":             "some-state-value",
		}

		fositeInvalidStateErrorQuery = map[string]string{
			"error":             "invalid_state",
			"error_description": "The state is missing or does not have enough characters and is therefore considered too weak\n\nRequest parameter \"state\" must be at least be 8 characters long to ensure sufficient entropy.",
			"error_hint":        `Request parameter "state" must be at least be 8 characters long to ensure sufficient entropy.`,
			"state":             "short",
		}

		fositeMissingResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method\n\nThe request is missing the \"response_type\"\" parameter.",
			"error_hint":        `The request is missing the "response_type"" parameter.`,
			"state":             "some-state-value",
		}
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
		AuthorizeCodes: map[string]storage.StoreAuthorizeCode{},
		PKCES:          map[string]fosite.Requester{},
	}

	happyStateGenerator := func() (state.State, error) { return "test-state", nil }
	happyPKCEGenerator := func() (pkce.Code, error) { return "test-pkce", nil }
	happyNonceGenerator := func() (nonce.Nonce, error) { return "test-nonce", nil }

	// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
	// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
	expectedUpstreamCodeChallenge := "VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"

	pathWithQuery := func(path string, query map[string]string) string {
		values := url.Values{}
		for k, v := range query {
			values[k] = []string{v}
		}
		pathToReturn := fmt.Sprintf("%s?%s", path, values.Encode())
		require.NotRegexp(t, "^http", pathToReturn, "pathWithQuery helper was used to create a URL")
		return pathToReturn
	}

	urlWithQuery := func(baseURL string, query map[string]string) string {
		values := url.Values{}
		for k, v := range query {
			values[k] = []string{v}
		}
		urlToReturn := fmt.Sprintf("%s?%s", baseURL, values.Encode())
		_, err := url.Parse(urlToReturn)
		require.NoError(t, err, "urlWithQuery helper was used to create an illegal URL")
		return urlToReturn
	}

	happyGetRequestQueryMap := map[string]string{
		"response_type":         "code",
		"scope":                 "openid profile email",
		"client_id":             "pinniped-cli",
		"state":                 "some-state-value",
		"nonce":                 "some-nonce-value",
		"code_challenge":        "some-challenge",
		"code_challenge_method": "S256",
		"redirect_uri":          downstreamRedirectURI,
	}

	happyGetRequestPath := pathWithQuery("/some/path", happyGetRequestQueryMap)

	modifiedHappyGetRequestPath := func(queryOverrides map[string]string) string {
		copyOfHappyGetRequestQueryMap := map[string]string{}
		for k, v := range happyGetRequestQueryMap {
			copyOfHappyGetRequestQueryMap[k] = v
		}
		for k, v := range queryOverrides {
			_, hasKey := copyOfHappyGetRequestQueryMap[k]
			if v == "" && hasKey {
				delete(copyOfHappyGetRequestQueryMap, k)
			} else {
				copyOfHappyGetRequestQueryMap[k] = v
			}
		}
		return pathWithQuery("/some/path", copyOfHappyGetRequestQueryMap)
	}

	happyGetRequestExpectedRedirectLocation := urlWithQuery(upstreamAuthURL.String(),
		map[string]string{
			"response_type":         "code",
			"access_type":           "offline",
			"scope":                 "scope1 scope2",
			"client_id":             "some-client-id",
			"state":                 "test-state",
			"nonce":                 "test-nonce",
			"code_challenge":        expectedUpstreamCodeChallenge,
			"code_challenge_method": "S256",
			"redirect_uri":          issuer + "/callback/some-idp",
		},
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
			wantBodyString: fmt.Sprintf(`<a href="%s">Found</a>.%s`,
				html.EscapeString(happyGetRequestExpectedRedirectLocation),
				"\n\n",
			),
			wantLocationHeader: happyGetRequestExpectedRedirectLocation,
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
				"response_type":         []string{"code"},
				"scope":                 []string{"openid profile email"},
				"client_id":             []string{"pinniped-cli"},
				"state":                 []string{"some-state-value"},
				"code_challenge":        []string{"some-challenge"},
				"code_challenge_method": []string{"S256"},
				"redirect_uri":          []string{downstreamRedirectURI},
			}.Encode(),
			wantStatus:         http.StatusFound,
			wantContentType:    "",
			wantBodyString:     "",
			wantLocationHeader: happyGetRequestExpectedRedirectLocation,
		},
		{
			name:            "downstream client does not exist",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   happyStateGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
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
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:               "response type is unsupported",
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream scopes do not match what is configured for client",
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"scope": "openid profile email tuna"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request",
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "missing client id in request",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:   happyStateGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "missing PKCE code_challenge in request", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "invalid value for PKCE code_challenge_method in request", // https://tools.ietf.org/html/rfc7636#section-4.3
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "when PKCE code_challenge_method in request is `plain`", // https://tools.ietf.org/html/rfc7636#section-4.3
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "plain"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing PKCE code_challenge_method in request", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "state does not have enough entropy",
			issuer:             issuer,
			idpListGetter:      newIDPListGetter(upstreamOIDCIdentityProvider),
			generateState:      happyStateGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"state": "short"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:     "",
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
			idpListGetter:   newIDPListGetter(), // empty
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: No upstream providers are configured\n",
		},
		{
			name:            "too many upstream providers are configured",
			issuer:          issuer,
			idpListGetter:   newIDPListGetter(upstreamOIDCIdentityProvider, upstreamOIDCIdentityProvider), // more than one not allowed
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

		if test.wantBodyJSON != "" {
			require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
		} else {
			require.Equal(t, test.wantBodyString, rsp.Body.String())
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
		test.wantLocationHeader = urlWithQuery(upstreamAuthURL.String(),
			map[string]string{
				"response_type":         "code",
				"access_type":           "offline",
				"scope":                 "other-scope1 other-scope2",
				"client_id":             "some-other-client-id",
				"state":                 "test-state",
				"nonce":                 "test-nonce",
				"code_challenge":        expectedUpstreamCodeChallenge,
				"code_challenge_method": "S256",
				"redirect_uri":          issuer + "/callback/some-other-idp",
			},
		)
		test.wantBodyString = fmt.Sprintf(`<a href="%s">Found</a>.%s`,
			html.EscapeString(test.wantLocationHeader),
			"\n\n",
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
