// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/oidctestutil"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func TestAuthorizationEndpoint(t *testing.T) {
	const (
		downstreamIssuer                       = "https://my-downstream-issuer.com/some-path"
		downstreamRedirectURI                  = "http://127.0.0.1/callback"
		downstreamRedirectURIWithDifferentPort = "http://127.0.0.1:42/callback"
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

		fositePromptHasNoneAndOtherValueErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nUsed unknown value \"[none login]\" for prompt parameter",
			"error_hint":        "Used unknown value \"[none login]\" for prompt parameter",
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeMissingCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nClients must include a code_challenge when performing the authorize code flow, but it is missing.",
			"error_hint":        "Clients must include a code_challenge when performing the authorize code flow, but it is missing.",
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeMissingCodeChallengeMethodErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nClients must use code_challenge_method=S256, plain is not allowed.",
			"error_hint":        "Clients must use code_challenge_method=S256, plain is not allowed.",
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeInvalidCodeChallengeErrorQuery = map[string]string{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nThe code_challenge_method is not supported, use S256 instead.",
			"error_hint":        "The code_challenge_method is not supported, use S256 instead.",
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeUnsupportedResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method\n\nThe client is not allowed to request response_type \"unsupported\".",
			"error_hint":        `The client is not allowed to request response_type "unsupported".`,
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeInvalidScopeErrorQuery = map[string]string{
			"error":             "invalid_scope",
			"error_description": "The requested scope is invalid, unknown, or malformed\n\nThe OAuth 2.0 Client is not allowed to request scope \"tuna\".",
			"error_hint":        `The OAuth 2.0 Client is not allowed to request scope "tuna".`,
			"state":             "some-state-value-that-is-32-byte",
		}

		fositeInvalidStateErrorQuery = map[string]string{
			"error":             "invalid_state",
			"error_description": "The state is missing or does not have enough characters and is therefore considered too weak\n\nRequest parameter \"state\" must be at least be 32 characters long to ensure sufficient entropy.",
			"error_hint":        `Request parameter "state" must be at least be 32 characters long to ensure sufficient entropy.`,
			"state":             "short",
		}

		fositeMissingResponseTypeErrorQuery = map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "The authorization server does not support obtaining a token using this method\n\nThe request is missing the \"response_type\"\" parameter.",
			"error_hint":        `The request is missing the "response_type"" parameter.`,
			"state":             "some-state-value-that-is-32-byte",
		}
	)

	upstreamAuthURL, err := url.Parse("https://some-upstream-idp:8443/auth")
	require.NoError(t, err)

	upstreamOIDCIdentityProvider := oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:             "some-idp",
		ClientID:         "some-client-id",
		AuthorizationURL: *upstreamAuthURL,
		Scopes:           []string{"scope1", "scope2"},
	}

	// Configure fosite the same way that the production code would, using NullStorage to turn off storage.
	oauthStore := oidc.NullStorage{}
	hmacSecret := []byte("some secret - must have at least 32 bytes")
	require.GreaterOrEqual(t, len(hmacSecret), 32, "fosite requires that hmac secrets have at least 32 bytes")
	jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
	oauthHelper := oidc.FositeOauth2Helper(oauthStore, downstreamIssuer, hmacSecret, jwksProviderIsUnused)

	happyCSRF := "test-csrf"
	happyPKCE := "test-pkce"
	happyNonce := "test-nonce-that-is-32-bytes-long"
	happyCSRFGenerator := func() (csrftoken.CSRFToken, error) { return csrftoken.CSRFToken(happyCSRF), nil }
	happyPKCEGenerator := func() (pkce.Code, error) { return pkce.Code(happyPKCE), nil }
	happyNonceGenerator := func() (nonce.Nonce, error) { return nonce.Nonce(happyNonce), nil }

	// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
	// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
	expectedUpstreamCodeChallenge := "VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"

	var stateEncoderHashKey = []byte("fake-hash-secret")
	var stateEncoderBlockKey = []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	var cookieEncoderHashKey = []byte("fake-hash-secret2")
	var cookieEncoderBlockKey = []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	var happyStateEncoder = securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateEncoder.SetSerializer(securecookie.JSONEncoder{})
	var happyCookieEncoder = securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieEncoder.SetSerializer(securecookie.JSONEncoder{})

	encodeQuery := func(query map[string]string) string {
		values := url.Values{}
		for k, v := range query {
			values[k] = []string{v}
		}
		return values.Encode()
	}

	pathWithQuery := func(path string, query map[string]string) string {
		pathToReturn := fmt.Sprintf("%s?%s", path, encodeQuery(query))
		require.NotRegexp(t, "^http", pathToReturn, "pathWithQuery helper was used to create a URL")
		return pathToReturn
	}

	urlWithQuery := func(baseURL string, query map[string]string) string {
		urlToReturn := fmt.Sprintf("%s?%s", baseURL, encodeQuery(query))
		_, err := url.Parse(urlToReturn)
		require.NoError(t, err, "urlWithQuery helper was used to create an illegal URL")
		return urlToReturn
	}

	happyGetRequestQueryMap := map[string]string{
		"response_type":         "code",
		"scope":                 "openid profile email",
		"client_id":             "pinniped-cli",
		"state":                 "some-state-value-that-is-32-byte",
		"nonce":                 "some-nonce-value",
		"code_challenge":        "some-challenge",
		"code_challenge_method": "S256",
		"redirect_uri":          downstreamRedirectURI,
	}

	happyGetRequestPath := pathWithQuery("/some/path", happyGetRequestQueryMap)

	modifiedHappyGetRequestQueryMap := func(queryOverrides map[string]string) map[string]string {
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
		return copyOfHappyGetRequestQueryMap
	}

	modifiedHappyGetRequestPath := func(queryOverrides map[string]string) string {
		return pathWithQuery("/some/path", modifiedHappyGetRequestQueryMap(queryOverrides))
	}

	expectedUpstreamStateParam := func(queryOverrides map[string]string, csrfValueOverride, upstreamNameOverride string) string {
		csrf := happyCSRF
		if csrfValueOverride != "" {
			csrf = csrfValueOverride
		}
		upstreamName := upstreamOIDCIdentityProvider.Name
		if upstreamNameOverride != "" {
			upstreamName = upstreamNameOverride
		}
		encoded, err := happyStateEncoder.Encode("s",
			oidctestutil.ExpectedUpstreamStateParamFormat{
				P: encodeQuery(modifiedHappyGetRequestQueryMap(queryOverrides)),
				U: upstreamName,
				N: happyNonce,
				C: csrf,
				K: happyPKCE,
				V: "1",
			},
		)
		require.NoError(t, err)
		return encoded
	}

	expectedRedirectLocation := func(expectedUpstreamState string) string {
		return urlWithQuery(upstreamAuthURL.String(), map[string]string{
			"response_type":         "code",
			"access_type":           "offline",
			"scope":                 "scope1 scope2",
			"client_id":             "some-client-id",
			"state":                 expectedUpstreamState,
			"nonce":                 happyNonce,
			"code_challenge":        expectedUpstreamCodeChallenge,
			"code_challenge_method": "S256",
			"redirect_uri":          downstreamIssuer + "/callback",
		})
	}

	incomingCookieCSRFValue := "csrf-value-from-cookie"
	encodedIncomingCookieCSRFValue, err := happyCookieEncoder.Encode("csrf", incomingCookieCSRFValue)
	require.NoError(t, err)

	type testCase struct {
		name string

		issuer        string
		idpListGetter provider.DynamicUpstreamIDPProvider
		generateCSRF  func() (csrftoken.CSRFToken, error)
		generatePKCE  func() (pkce.Code, error)
		generateNonce func() (nonce.Nonce, error)
		stateEncoder  oidc.Codec
		cookieEncoder oidc.Codec
		method        string
		path          string
		contentType   string
		body          string
		csrfCookie    string

		wantStatus                  int
		wantContentType             string
		wantBodyString              string
		wantBodyJSON                string
		wantLocationHeader          string
		wantCSRFValueInCookieHeader string

		wantUpstreamStateParamInLocationHeader bool
		wantBodyStringWithLocationInHref       bool
	}
	tests := []testCase{
		{
			name:                                   "happy path using GET without a CSRF cookie",
			issuer:                                 downstreamIssuer,
			idpListGetter:                          oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath,
			wantStatus:                             http.StatusFound,
			wantContentType:                        "text/html; charset=utf-8",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocation(expectedUpstreamStateParam(nil, "", "")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "happy path using GET with a CSRF cookie",
			issuer:                                 downstreamIssuer,
			idpListGetter:                          oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodGet,
			path:                                   happyGetRequestPath,
			csrfCookie:                             "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue + " ",
			wantStatus:                             http.StatusFound,
			wantContentType:                        "text/html; charset=utf-8",
			wantLocationHeader:                     expectedRedirectLocation(expectedUpstreamStateParam(nil, incomingCookieCSRFValue, "")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:                                   "happy path using POST",
			issuer:                                 downstreamIssuer,
			idpListGetter:                          oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:                           happyCSRFGenerator,
			generatePKCE:                           happyPKCEGenerator,
			generateNonce:                          happyNonceGenerator,
			stateEncoder:                           happyStateEncoder,
			cookieEncoder:                          happyCookieEncoder,
			method:                                 http.MethodPost,
			path:                                   "/some/path",
			contentType:                            "application/x-www-form-urlencoded",
			body:                                   encodeQuery(happyGetRequestQueryMap),
			wantStatus:                             http.StatusFound,
			wantContentType:                        "",
			wantBodyString:                         "",
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocation(expectedUpstreamStateParam(nil, "", "")),
			wantUpstreamStateParamInLocationHeader: true,
		},
		{
			name:            "error while decoding CSRF cookie just generates a new cookie and succeeds as usual",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusFound,
			wantContentType: "text/html; charset=utf-8",
			// Generated a new CSRF cookie and set it in the response.
			wantCSRFValueInCookieHeader:            happyCSRF,
			wantLocationHeader:                     expectedRedirectLocation(expectedUpstreamStateParam(nil, "", "")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "happy path when downstream redirect uri matches what is configured for client except for the port number",
			issuer:        downstreamIssuer,
			idpListGetter: oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}),
			wantStatus:                  http.StatusFound,
			wantContentType:             "text/html; charset=utf-8",
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocation(expectedUpstreamStateParam(map[string]string{
				"redirect_uri": downstreamRedirectURIWithDifferentPort, // not the same port number that is registered for the client
			}, "", "")),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:          "downstream redirect uri does not match what is configured for client",
			issuer:        downstreamIssuer,
			idpListGetter: oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			path: modifiedHappyGetRequestPath(map[string]string{
				"redirect_uri": "http://127.0.0.1/does-not-match-what-is-configured-for-pinniped-cli-client",
			}),
			wantStatus:      http.StatusBadRequest,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidRedirectURIErrorBody,
		},
		{
			name:            "downstream client does not exist",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": "invalid-client"}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "response type is unsupported",
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": "unsupported"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeUnsupportedResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "downstream scopes do not match what is configured for client",
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"scope": "openid profile email tuna"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidScopeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing response type in request",
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"response_type": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingResponseTypeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "missing client id in request",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            modifiedHappyGetRequestPath(map[string]string{"client_id": ""}),
			wantStatus:      http.StatusUnauthorized,
			wantContentType: "application/json; charset=utf-8",
			wantBodyJSON:    fositeInvalidClientErrorBody,
		},
		{
			name:               "missing PKCE code_challenge in request", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "invalid value for PKCE code_challenge_method in request", // https://tools.ietf.org/html/rfc7636#section-4.3
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "this-is-not-a-valid-pkce-alg"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidCodeChallengeErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "when PKCE code_challenge_method in request is `plain`", // https://tools.ietf.org/html/rfc7636#section-4.3
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": "plain"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			name:               "missing PKCE code_challenge_method in request", // See https://tools.ietf.org/html/rfc7636#section-4.4.1
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"code_challenge_method": ""}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeMissingCodeChallengeMethodErrorQuery),
			wantBodyString:     "",
		},
		{
			// This is just one of the many OIDC validations run by fosite. This test is to ensure that we are running
			// through that part of the fosite library.
			name:               "prompt param is not allowed to have none and another legal value at the same time",
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"prompt": "none login"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositePromptHasNoneAndOtherValueErrorQuery),
			wantBodyString:     "",
		},
		{
			name:          "OIDC validations are skipped when the openid scope was not requested",
			issuer:        downstreamIssuer,
			idpListGetter: oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:  happyCSRFGenerator,
			generatePKCE:  happyPKCEGenerator,
			generateNonce: happyNonceGenerator,
			stateEncoder:  happyStateEncoder,
			cookieEncoder: happyCookieEncoder,
			method:        http.MethodGet,
			// The following prompt value is illegal when openid is requested, but note that openid is not requested.
			path:                        modifiedHappyGetRequestPath(map[string]string{"prompt": "none login", "scope": "email"}),
			wantStatus:                  http.StatusFound,
			wantContentType:             "text/html; charset=utf-8",
			wantCSRFValueInCookieHeader: happyCSRF,
			wantLocationHeader: expectedRedirectLocation(expectedUpstreamStateParam(
				map[string]string{"prompt": "none login", "scope": "email"}, "", "",
			)),
			wantUpstreamStateParamInLocationHeader: true,
			wantBodyStringWithLocationInHref:       true,
		},
		{
			name:               "state does not have enough entropy",
			issuer:             downstreamIssuer,
			idpListGetter:      oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:       happyCSRFGenerator,
			generatePKCE:       happyPKCEGenerator,
			generateNonce:      happyNonceGenerator,
			stateEncoder:       happyStateEncoder,
			cookieEncoder:      happyCookieEncoder,
			method:             http.MethodGet,
			path:               modifiedHappyGetRequestPath(map[string]string{"state": "short"}),
			wantStatus:         http.StatusFound,
			wantContentType:    "application/json; charset=utf-8",
			wantLocationHeader: urlWithQuery(downstreamRedirectURI, fositeInvalidStateErrorQuery),
			wantBodyString:     "",
		},
		{
			name:            "error while encoding upstream state param",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    &errorReturningEncoder{},
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error encoding upstream state param\n",
		},
		{
			name:            "error while encoding CSRF cookie value for new cookie",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   &errorReturningEncoder{},
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error encoding CSRF cookie\n",
		},
		{
			name:            "error while generating CSRF token",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    func() (csrftoken.CSRFToken, error) { return "", fmt.Errorf("some csrf generator error") },
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating CSRF token\n",
		},
		{
			name:            "error while generating nonce",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    happyPKCEGenerator,
			generateNonce:   func() (nonce.Nonce, error) { return "", fmt.Errorf("some nonce generator error") },
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating nonce param\n",
		},
		{
			name:            "error while generating PKCE",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			generateCSRF:    happyCSRFGenerator,
			generatePKCE:    func() (pkce.Code, error) { return "", fmt.Errorf("some PKCE generator error") },
			generateNonce:   happyNonceGenerator,
			stateEncoder:    happyStateEncoder,
			cookieEncoder:   happyCookieEncoder,
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusInternalServerError,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Internal Server Error: error generating PKCE param\n",
		},
		{
			name:            "no upstream providers are configured",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(), // empty
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: No upstream providers are configured\n",
		},
		{
			name:            "too many upstream providers are configured",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider, &upstreamOIDCIdentityProvider), // more than one not allowed
			method:          http.MethodGet,
			path:            happyGetRequestPath,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Unprocessable Entity: Too many upstream providers are configured (support for multiple upstreams is not yet implemented)\n",
		},
		{
			name:            "PUT is a bad method",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			method:          http.MethodPut,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PUT (try GET or POST)\n",
		},
		{
			name:            "PATCH is a bad method",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
			method:          http.MethodPatch,
			path:            "/some/path",
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: "text/plain; charset=utf-8",
			wantBodyString:  "Method Not Allowed: PATCH (try GET or POST)\n",
		},
		{
			name:            "DELETE is a bad method",
			issuer:          downstreamIssuer,
			idpListGetter:   oidctestutil.NewIDPListGetter(&upstreamOIDCIdentityProvider),
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
		if test.csrfCookie != "" {
			req.Header.Set("Cookie", test.csrfCookie)
		}
		rsp := httptest.NewRecorder()
		subject.ServeHTTP(rsp, req)
		t.Logf("response: %#v", rsp)
		t.Logf("response body: %q", rsp.Body.String())

		require.Equal(t, test.wantStatus, rsp.Code)
		testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

		actualLocation := rsp.Header().Get("Location")
		if test.wantLocationHeader != "" {
			if test.wantUpstreamStateParamInLocationHeader {
				requireEqualDecodedStateParams(t, actualLocation, test.wantLocationHeader, test.stateEncoder)
			}
			// The upstream state param is encoded using a timestamp at the beginning so we don't want to
			// compare those states since they may be different, but we do want to compare the downstream
			// state param that should be exactly the same.
			requireEqualURLs(t, actualLocation, test.wantLocationHeader, test.wantUpstreamStateParamInLocationHeader)
		} else {
			require.Empty(t, rsp.Header().Values("Location"))
		}

		switch {
		case test.wantBodyJSON != "":
			require.JSONEq(t, test.wantBodyJSON, rsp.Body.String())
		case test.wantBodyStringWithLocationInHref:
			anchorTagWithLocationHref := fmt.Sprintf("<a href=\"%s\">Found</a>.\n\n", html.EscapeString(actualLocation))
			require.Equal(t, anchorTagWithLocationHref, rsp.Body.String())
		default:
			require.Equal(t, test.wantBodyString, rsp.Body.String())
		}

		if test.wantCSRFValueInCookieHeader != "" {
			require.Len(t, rsp.Header().Values("Set-Cookie"), 1)
			actualCookie := rsp.Header().Get("Set-Cookie")
			regex := regexp.MustCompile("__Host-pinniped-csrf=([^;]+); Path=/; HttpOnly; Secure; SameSite=Lax")
			submatches := regex.FindStringSubmatch(actualCookie)
			require.Len(t, submatches, 2)
			captured := submatches[1]
			var decodedCSRFCookieValue string
			err := test.cookieEncoder.Decode("csrf", captured, &decodedCSRFCookieValue)
			require.NoError(t, err)
			require.Equal(t, test.wantCSRFValueInCookieHeader, decodedCSRFCookieValue)
		} else {
			require.Empty(t, rsp.Header().Values("Set-Cookie"))
		}
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			subject := NewHandler(test.issuer, test.idpListGetter, oauthHelper, test.generateCSRF, test.generatePKCE, test.generateNonce, test.stateEncoder, test.cookieEncoder)
			runOneTestCase(t, test, subject)
		})
	}

	t.Run("allows upstream provider configuration to change between requests", func(t *testing.T) {
		test := tests[0]
		require.Equal(t, "happy path using GET without a CSRF cookie", test.name) // re-use the happy path test case

		subject := NewHandler(test.issuer, test.idpListGetter, oauthHelper, test.generateCSRF, test.generatePKCE, test.generateNonce, test.stateEncoder, test.cookieEncoder)

		runOneTestCase(t, test, subject)

		// Call the setter to change the upstream IDP settings.
		newProviderSettings := oidctestutil.TestUpstreamOIDCIdentityProvider{
			Name:             "some-other-idp",
			ClientID:         "some-other-client-id",
			AuthorizationURL: *upstreamAuthURL,
			Scopes:           []string{"other-scope1", "other-scope2"},
		}
		test.idpListGetter.SetIDPList([]provider.UpstreamOIDCIdentityProviderI{provider.UpstreamOIDCIdentityProviderI(&newProviderSettings)})

		// Update the expectations of the test case to match the new upstream IDP settings.
		test.wantLocationHeader = urlWithQuery(upstreamAuthURL.String(),
			map[string]string{
				"response_type":         "code",
				"access_type":           "offline",
				"scope":                 "other-scope1 other-scope2",
				"client_id":             "some-other-client-id",
				"state":                 expectedUpstreamStateParam(nil, "", newProviderSettings.Name),
				"nonce":                 happyNonce,
				"code_challenge":        expectedUpstreamCodeChallenge,
				"code_challenge_method": "S256",
				"redirect_uri":          downstreamIssuer + "/callback",
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

type errorReturningEncoder struct {
	oidc.Codec
}

func (*errorReturningEncoder) Encode(_ string, _ interface{}) (string, error) {
	return "", fmt.Errorf("some encoding error")
}

func requireEqualDecodedStateParams(t *testing.T, actualURL string, expectedURL string, stateParamDecoder oidc.Codec) {
	t.Helper()
	actualLocationURL, err := url.Parse(actualURL)
	require.NoError(t, err)
	expectedLocationURL, err := url.Parse(expectedURL)
	require.NoError(t, err)

	expectedQueryStateParam := expectedLocationURL.Query().Get("state")
	require.NotEmpty(t, expectedQueryStateParam)
	var expectedDecodedStateParam oidctestutil.ExpectedUpstreamStateParamFormat
	err = stateParamDecoder.Decode("s", expectedQueryStateParam, &expectedDecodedStateParam)
	require.NoError(t, err)

	actualQueryStateParam := actualLocationURL.Query().Get("state")
	require.NotEmpty(t, actualQueryStateParam)
	var actualDecodedStateParam oidctestutil.ExpectedUpstreamStateParamFormat
	err = stateParamDecoder.Decode("s", actualQueryStateParam, &actualDecodedStateParam)
	require.NoError(t, err)

	require.Equal(t, expectedDecodedStateParam, actualDecodedStateParam)
}

func requireEqualURLs(t *testing.T, actualURL string, expectedURL string, ignoreState bool) {
	t.Helper()
	actualLocationURL, err := url.Parse(actualURL)
	require.NoError(t, err)
	expectedLocationURL, err := url.Parse(expectedURL)
	require.NoError(t, err)
	require.Equal(t, expectedLocationURL.Scheme, actualLocationURL.Scheme,
		"schemes were not equal: expected %s but got %s", expectedURL, actualURL,
	)
	require.Equal(t, expectedLocationURL.User, actualLocationURL.User,
		"users were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	require.Equal(t, expectedLocationURL.Host, actualLocationURL.Host,
		"hosts were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	require.Equal(t, expectedLocationURL.Path, actualLocationURL.Path,
		"paths were not equal: expected %s but got %s", expectedURL, actualURL,
	)

	expectedLocationQuery := expectedLocationURL.Query()
	actualLocationQuery := actualLocationURL.Query()
	// Let the caller ignore the state, since it may contain a digest at the end that is difficult to
	// predict because it depends on a time.Now() timestamp.
	if ignoreState {
		expectedLocationQuery.Del("state")
		actualLocationQuery.Del("state")
	}
	require.Equal(t, expectedLocationQuery, actualLocationQuery)
}
