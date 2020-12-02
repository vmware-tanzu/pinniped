// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
)

const (
	goodIssuer           = "https://some-issuer.com"
	goodClient           = "pinniped-cli"
	goodRedirectURI      = "http://127.0.0.1/callback"
	goodPKCECodeVerifier = "some-pkce-verifier-that-must-be-at-least-43-characters-to-meet-entropy-requirements"
	goodNonce            = "some-nonce-that-is-at-least-32-characters-to-meet-entropy-requirements"
	goodSubject          = "some-subject"
	goodUsername         = "some-username"

	hmacSecret = "this needs to be at least 32 characters to meet entropy requirements"

	authCodeExpirationSeconds    = 3 * 60 // Current, we set our auth code expiration to 3 minutes
	accessTokenExpirationSeconds = 5 * 60 // Currently, we set our access token expiration to 5 minutes
	idTokenExpirationSeconds     = 5 * 60 // Currently, we set our ID token expiration to 5 minutes

	timeComparisonFudgeSeconds = 15
)

var (
	goodAuthTime        = time.Date(1, 2, 3, 4, 5, 6, 7, time.Local)
	goodRequestedAtTime = time.Date(7, 6, 5, 4, 3, 2, 1, time.Local)

	fositeInvalidMethodErrorBody = func(actual string) string {
		return here.Docf(`
			{
				"error":             "invalid_request",
				"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
				"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nHTTP method is \"%s\", expected \"POST\".",
				"error_hint":        "HTTP method is \"%s\", expected \"POST\".",
				"status_code":       400
			 }
		`, actual, actual)
	}

	fositeMissingGrantTypeErrorBody = here.Docf(`
		{
			"error":             "invalid_request",
			"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nRequest parameter \"grant_type\"\" is missing",
			"error_hint":        "Request parameter \"grant_type\"\" is missing",
			"status_code":       400
		}
	`)

	fositeEmptyPayloadErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nThe POST body can not be empty.",
			"error_hint":        "The POST body can not be empty.",
			"status_code":       400
		}
	`)

	fositeInvalidPayloadErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nUnable to parse HTTP body, make sure to send a properly formatted form request body.",
			"error_hint":        "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
			"status_code":       400
		}
	`)

	fositeInvalidRequestErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nMake sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			"error_hint":        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			"status_code":       400
		}
	`)

	fositeMissingClientErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_verbose":     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed\n\nClient credentials missing or malformed in both HTTP Authorization header and HTTP POST body.",
			"error_hint":        "Client credentials missing or malformed in both HTTP Authorization header and HTTP POST body.",
			"status_code":       400
		}
	`)

	fositeInvalidClientErrorBody = here.Doc(`
		{
			"error":             "invalid_client",
			"error_verbose":     "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)",
			"error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)",
			"status_code":       401
		}
	`)

	fositeInvalidAuthCodeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_verbose":     "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"status_code":       400
		}
	`)

	fositeReusedAuthCodeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_verbose":     "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client\n\nThe authorization code has already been used.",
			"error_hint":        "The authorization code has already been used.",
			"status_code":       400
		}
	`)

	fositeInvalidRedirectURIErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_verbose":     "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client\n\nThe \"redirect_uri\" from this request does not match the one from the authorize request.",
			"error_hint":        "The \"redirect_uri\" from this request does not match the one from the authorize request.",
			"status_code":       400
		}
	`)

	fositeMissingPKCEVerifierErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_verbose":     "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client\n\nThe PKCE code verifier must be at least 43 characters.",
			"error_hint":        "The PKCE code verifier must be at least 43 characters.",
			"status_code":       400
		}
	`)

	fositeWrongPKCEVerifierErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_verbose":     "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client\n\nThe PKCE code challenge did not match the code verifier.",
			"error_hint":        "The PKCE code challenge did not match the code verifier.",
			"status_code":       400
		}
	`)
)

func TestTokenEndpoint(t *testing.T) {
	happyAuthRequest := &http.Request{
		Form: url.Values{
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"client_id":             {goodClient},
			"state":                 {"some-state-value-that-is-32-byte"},
			"nonce":                 {goodNonce},
			"code_challenge":        {doSHA256(goodPKCECodeVerifier)},
			"code_challenge_method": {"S256"},
			"redirect_uri":          {goodRedirectURI},
		},
	}

	tests := []struct {
		name string

		authRequest func(authRequest *http.Request)
		storage     func(t *testing.T, s *storage.MemoryStore, authCode string)
		request     func(r *http.Request, authCode string)

		wantStatus     int
		wantBodyFields []string
		wantExactBody  string
	}{
		// happy path
		{
			name:           "request is valid and tokens are issued",
			wantStatus:     http.StatusOK,
			wantBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"},
		},
		{
			name: "openid scope was not requested from authorize endpoint",
			authRequest: func(authRequest *http.Request) {
				authRequest.Form.Set("scope", "profile email")
			},
			wantStatus:     http.StatusOK,
			wantBodyFields: []string{"access_token", "token_type", "scope", "expires_in"},
		},

		// sad path
		{
			name:          "GET method is wrong",
			request:       func(r *http.Request, authCode string) { r.Method = http.MethodGet },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidMethodErrorBody("GET"),
		},
		{
			name:          "PUT method is wrong",
			request:       func(r *http.Request, authCode string) { r.Method = http.MethodPut },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidMethodErrorBody("PUT"),
		},
		{
			name:          "PATCH method is wrong",
			request:       func(r *http.Request, authCode string) { r.Method = http.MethodPatch },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidMethodErrorBody("PATCH"),
		},
		{
			name:          "DELETE method is wrong",
			request:       func(r *http.Request, authCode string) { r.Method = http.MethodDelete },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidMethodErrorBody("DELETE"),
		},
		{
			name:          "content type is invalid",
			request:       func(r *http.Request, authCode string) { r.Header.Set("Content-Type", "text/plain") },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeEmptyPayloadErrorBody,
		},
		{
			name: "payload is not valid form serialization",
			request: func(r *http.Request, authCode string) {
				r.Body = ioutil.NopCloser(strings.NewReader("this newline character is not allowed in a form serialization: \n"))
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeMissingGrantTypeErrorBody,
		},
		{
			name:          "payload is empty",
			request:       func(r *http.Request, authCode string) { r.Body = nil },
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidPayloadErrorBody,
		},
		{
			name: "grant type is missing in request",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithGrantType("").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeMissingGrantTypeErrorBody,
		},
		{
			name: "grant type is not authorization_code",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithGrantType("bogus").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidRequestErrorBody,
		},
		{
			name: "client id is missing in request",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithClientID("").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeMissingClientErrorBody,
		},
		{
			name: "client id is wrong",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithClientID("bogus").ReadCloser()
			},
			wantStatus:    http.StatusUnauthorized,
			wantExactBody: fositeInvalidClientErrorBody,
		},
		{
			name: "auth code is missing in request",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithAuthCode("").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidAuthCodeErrorBody,
		},
		{
			name: "auth code has never been valid",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithAuthCode("bogus").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidAuthCodeErrorBody,
		},
		{
			name: "auth code is invalidated",
			storage: func(t *testing.T, s *storage.MemoryStore, authCode string) {
				err := s.InvalidateAuthorizeCodeSession(context.Background(), getFositeDataSignature(t, authCode))
				require.NoError(t, err)
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeReusedAuthCodeErrorBody,
		},
		{
			name: "redirect uri is missing in request",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithRedirectURI("").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidRedirectURIErrorBody,
		},
		{
			name: "redirect uri is wrong",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithRedirectURI("bogus").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeInvalidRedirectURIErrorBody,
		},
		{
			name: "pkce is missing in request",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithPKCE("").ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeMissingPKCEVerifierErrorBody,
		},
		{
			name: "pkce is wrong",
			request: func(r *http.Request, authCode string) {
				r.Body = happyBody(authCode).WithPKCE(
					"bogus-verifier-that-is-at-least-43-characters-for-the-sake-of-entropy",
				).ReadCloser()
			},
			wantStatus:    http.StatusBadRequest,
			wantExactBody: fositeWrongPKCEVerifierErrorBody,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			authRequest := deepCopyRequestForm(happyAuthRequest)
			if test.authRequest != nil {
				test.authRequest(authRequest)
			}

			oauthStore := storage.NewMemoryStore()
			oauthHelper, authCode := makeHappyOauthHelper(t, authRequest, oauthStore)
			if test.storage != nil {
				test.storage(t, oauthStore, authCode)
			}
			subject := NewHandler(oauthHelper)

			req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyBody(authCode).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.request != nil {
				test.request(req, authCode)
			}
			rsp := httptest.NewRecorder()

			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			require.Equal(t, test.wantStatus, rsp.Code)
			requireEqualContentType(t, rsp.Header().Get("Content-Type"), "application/json")
			if test.wantBodyFields != nil {
				var m map[string]interface{}
				require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &m))
				require.ElementsMatch(t, test.wantBodyFields, getMapKeys(m))

				code := req.PostForm.Get("code")
				wantOpenidScope := contains(test.wantBodyFields, "id_token")
				requireInvalidAuthCodeStorage(t, code, oauthStore)
				requireValidAccessTokenStorage(t, m, oauthStore, wantOpenidScope)
				requireInvalidPKCEStorage(t, code, oauthStore)
				requireValidOIDCStorage(t, m, code, oauthStore, wantOpenidScope)
			} else {
				require.JSONEq(t, test.wantExactBody, rsp.Body.String())
			}
		})
	}

	t.Run("auth code is used twice", func(t *testing.T) {
		authRequest := deepCopyRequestForm(happyAuthRequest)
		oauthStore := storage.NewMemoryStore()
		oauthHelper, authCode := makeHappyOauthHelper(t, authRequest, oauthStore)
		subject := NewHandler(oauthHelper)

		req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyBody(authCode).ReadCloser())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// First call - should be successful.
		rsp0 := httptest.NewRecorder()
		subject.ServeHTTP(rsp0, req)
		t.Logf("response 0: %#v", rsp0)
		t.Logf("response 0 body: %q", rsp0.Body.String())
		requireEqualContentType(t, rsp0.Header().Get("Content-Type"), "application/json")
		require.Equal(t, http.StatusOK, rsp0.Code)

		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(rsp0.Body.Bytes(), &m))

		wantBodyFields := []string{"id_token", "access_token", "token_type", "expires_in", "scope"}
		require.ElementsMatch(t, wantBodyFields, getMapKeys(m))

		code := req.PostForm.Get("code")
		wantOpenidScope := true
		requireInvalidAuthCodeStorage(t, code, oauthStore)
		requireValidAccessTokenStorage(t, m, oauthStore, wantOpenidScope)
		requireInvalidPKCEStorage(t, code, oauthStore)
		requireValidOIDCStorage(t, m, code, oauthStore, wantOpenidScope)

		// Second call - should be unsuccessful since auth code was already used.
		//
		// Fosite will also revoke the access token as is recommended by the OIDC spec. Currently, we don't
		// delete the OIDC storage...but we probably should.
		rsp1 := httptest.NewRecorder()
		subject.ServeHTTP(rsp1, req)
		t.Logf("response 1: %#v", rsp1)
		t.Logf("response 1 body: %q", rsp1.Body.String())
		require.Equal(t, http.StatusBadRequest, rsp1.Code)
		requireEqualContentType(t, rsp1.Header().Get("Content-Type"), "application/json")
		require.JSONEq(t, fositeReusedAuthCodeErrorBody, rsp1.Body.String())

		requireInvalidAuthCodeStorage(t, code, oauthStore)
		requireInvalidAccessTokenStorage(t, m, oauthStore)
		requireInvalidPKCEStorage(t, code, oauthStore)
		requireValidOIDCStorage(t, m, code, oauthStore, wantOpenidScope)
	})
}

type body url.Values

func happyBody(happyAuthCode string) body {
	return map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {happyAuthCode},
		"redirect_uri":  {goodRedirectURI},
		"code_verifier": {goodPKCECodeVerifier},
		"client_id":     {goodClient},
	}
}

func (b body) WithGrantType(grantType string) body {
	return b.with("grant_type", grantType)
}

func (b body) WithClientID(clientID string) body {
	return b.with("client_id", clientID)
}

func (b body) WithAuthCode(code string) body {
	return b.with("code", code)
}

func (b body) WithRedirectURI(redirectURI string) body {
	return b.with("redirect_uri", redirectURI)
}

func (b body) WithPKCE(verifier string) body {
	return b.with("code_verifier", verifier)
}

func (b body) ReadCloser() io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(url.Values(b).Encode()))
}

func (b body) with(param, value string) body {
	if value == "" {
		url.Values(b).Del(param)
	} else {
		url.Values(b).Set(param, value)
	}
	return b
}

// getFositeDataSignature returns the signature of the provided data. The provided data could be an auth code, access
// token, etc. It is assumed that the code is of the format "data.signature", which is how Fosite generates auth codes
// and access tokens.
func getFositeDataSignature(t *testing.T, data string) string {
	split := strings.Split(data, ".")
	require.Len(t, split, 2)
	return split[1]
}

func makeHappyOauthHelper(
	t *testing.T,
	authRequest *http.Request,
	store *storage.MemoryStore,
) (fosite.OAuth2Provider, string) {
	t.Helper()

	jwtSigningKey := generateJWTSigningKey(t)
	oauthHelper := oidc.FositeOauth2Helper(goodIssuer, store, []byte(hmacSecret), jwtSigningKey)

	// Add the Pinniped CLI client.
	store.Clients[goodClient] = oidc.PinnipedCLIOIDCClient()

	// Simulate the auth endpoint running so Fosite code will fill the store with realistic values.
	//
	// We only set the fields in the session that Fosite wants us to set.
	ctx := context.Background()
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     goodSubject,
			AuthTime:    goodAuthTime,
			RequestedAt: goodRequestedAtTime,
		},
		Subject:  goodSubject,
		Username: goodUsername,
	}
	authRequester, err := oauthHelper.NewAuthorizeRequest(ctx, authRequest)
	require.NoError(t, err)
	if strings.Contains(authRequest.Form.Get("scope"), "openid") {
		authRequester.GrantScope("openid")
	}
	authResponder, err := oauthHelper.NewAuthorizeResponse(ctx, authRequester, session)
	require.NoError(t, err)

	return oauthHelper, authResponder.GetCode()
}

func generateJWTSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func hashAccessToken(accessToken string) string {
	// See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken.
	// "Access Token hash value. Its value is the base64url encoding of the left-most half of
	// the hash of the octets of the ASCII representation of the access_token value, where the
	// hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID
	// Token's JOSE Header."
	b := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(b[:len(b)/2])
}

func doSHA256(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func requireInvalidAuthCodeStorage(
	t *testing.T,
	code string,
	storage *storage.MemoryStore,
) {
	t.Helper()

	// Make sure we have invalidated this auth code.
	_, err := storage.GetAuthorizeCodeSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.Equal(t, fosite.ErrInvalidatedAuthorizeCode, err)
}

func requireValidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage *storage.MemoryStore,
	wantGrantedOpenidScope bool,
) {
	t.Helper()

	// Get the access token, and make sure we can use it to perform a lookup on the storage.
	accessToken, ok := body["access_token"]
	require.True(t, ok)
	accessTokenString, ok := accessToken.(string)
	require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
	authRequest, err := storage.GetAccessTokenSession(context.Background(), getFositeDataSignature(t, accessTokenString), nil)
	require.NoError(t, err)

	// Make sure the other body fields are valid.
	tokenType, ok := body["token_type"]
	require.True(t, ok)
	tokenTypeString, ok := tokenType.(string)
	require.Truef(t, ok, "wanted token_type to be a string, but got %T", tokenType)
	require.Equal(t, "bearer", tokenTypeString)

	expiresIn, ok := body["expires_in"]
	require.True(t, ok)
	expiresInNumber, ok := expiresIn.(float64) // Go unmarshals JSON numbers to float64, see `go doc encoding/json`
	require.Truef(t, ok, "wanted expires_in to be an float64, but got %T", expiresIn)
	require.InDelta(t, accessTokenExpirationSeconds, expiresInNumber, timeComparisonFudgeSeconds)

	scopes, ok := body["scope"]
	require.True(t, ok)
	scopesString, ok := scopes.(string)
	require.Truef(t, ok, "wanted scopes to be an string, but got %T", scopes)
	wantScopes := ""
	if wantGrantedOpenidScope {
		wantScopes += "openid"
	}
	require.Equal(t, wantScopes, scopesString)

	// Fosite stores access tokens without any of the original request form pararmeters.
	requireValidAuthRequest(
		t,
		authRequest,
		authRequest.Sanitize([]string{}).GetRequestForm(),
		hashAccessToken(accessTokenString),
		wantGrantedOpenidScope,
	)
}

func requireInvalidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage *storage.MemoryStore,
) {
	t.Helper()

	// Get the access token, and make sure we can use it to perform a lookup on the storage.
	accessToken, ok := body["access_token"]
	require.True(t, ok)
	accessTokenString, ok := accessToken.(string)
	require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
	_, err := storage.GetAccessTokenSession(context.Background(), getFositeDataSignature(t, accessTokenString), nil)
	require.Equal(t, fosite.ErrNotFound, err)
}

func requireInvalidPKCEStorage(
	t *testing.T,
	code string,
	storage *storage.MemoryStore,
) {
	t.Helper()

	// Make sure the PKCE session has been deleted. Note that Fosite stores PKCE codes using the auth code signature
	// as a key.
	_, err := storage.GetPKCERequestSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.Equal(t, fosite.ErrNotFound, err)
}

func requireValidOIDCStorage(
	t *testing.T,
	body map[string]interface{},
	code string,
	storage *storage.MemoryStore,
	wantGrantedOpenidScope bool,
) {
	t.Helper()

	if wantGrantedOpenidScope {
		// Make sure the OIDC session is still there. Note that Fosite stores OIDC sessions using the full auth code as a key.
		authRequest, err := storage.GetOpenIDConnectSession(context.Background(), code, nil)
		require.NoError(t, err)

		// Fosite stores OIDC sessions with only the nonce in the original request form.
		accessToken, ok := body["access_token"]
		require.True(t, ok)
		accessTokenString, ok := accessToken.(string)
		require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
		requireValidAuthRequest(
			t,
			authRequest,
			authRequest.Sanitize([]string{"nonce"}).GetRequestForm(),
			hashAccessToken(accessTokenString),
			true,
		)
	} else {
		_, err := storage.GetOpenIDConnectSession(context.Background(), code, nil)
		require.Equal(t, fosite.ErrNotFound, err)
	}
}

func requireValidAuthRequest(
	t *testing.T,
	authRequest fosite.Requester,
	wantRequestForm url.Values,
	wantAccessTokenHash string,
	wantGrantedOpenidScope bool,
) {
	t.Helper()

	// Assert that the getters on the authRequest return what we think they should.
	wantRequestedScopes := []string{"profile", "email"}
	wantGrantedScopes := []string{}
	if wantGrantedOpenidScope {
		wantRequestedScopes = append([]string{"openid"}, wantRequestedScopes...)
		wantGrantedScopes = append([]string{"openid"}, wantGrantedScopes...)
	}
	require.NotEmpty(t, authRequest.GetID())
	requireTimeInDelta(t, authRequest.GetRequestedAt(), time.Now().UTC(), timeComparisonFudgeSeconds*time.Second)
	require.Equal(t, goodClient, authRequest.GetClient().GetID())
	require.Equal(t, fosite.Arguments(wantRequestedScopes), authRequest.GetRequestedScopes())
	require.Equal(t, fosite.Arguments(wantGrantedScopes), authRequest.GetGrantedScopes())
	require.Empty(t, authRequest.GetRequestedAudience())
	require.Empty(t, authRequest.GetGrantedAudience())
	require.Equal(t, wantRequestForm, authRequest.GetRequestForm()) // Fosite stores access token request without form

	// Cast session to the type we think it should be.
	session, ok := authRequest.GetSession().(*openid.DefaultSession)
	require.Truef(t, ok, "could not cast %T to %T", authRequest.GetSession(), &openid.DefaultSession{})

	// Assert that the session claims are what we think they should be, but only if we are doing OIDC.
	if wantGrantedOpenidScope {
		claims := session.Claims
		require.Empty(t, claims.JTI) // When claims.JTI is empty, Fosite will generate a UUID for this field.
		require.Equal(t, goodIssuer, claims.Issuer)
		require.Equal(t, goodSubject, claims.Subject)
		require.Equal(t, []string{goodClient}, claims.Audience)
		require.Equal(t, goodNonce, claims.Nonce)
		requireTimeInDelta(
			t,
			time.Now().UTC().Add(idTokenExpirationSeconds*time.Second),
			claims.ExpiresAt,
			timeComparisonFudgeSeconds*time.Second,
		)
		requireTimeInDelta(t, time.Now().UTC(), claims.IssuedAt, timeComparisonFudgeSeconds*time.Second)
		require.Equal(t, wantAccessTokenHash, claims.AccessTokenHash)

		// We are in charge of setting these fields. For the purpose of testing, we ensure that the
		// sentinel test value is set correctly.
		require.Equal(t, goodRequestedAtTime, claims.RequestedAt)
		require.Equal(t, goodAuthTime, claims.AuthTime)

		// At this time, we don't use any of these optional (per the OIDC spec) fields.
		require.Empty(t, claims.AuthenticationContextClassReference)
		require.Empty(t, claims.AuthenticationMethodsReference)
		require.Empty(t, claims.CodeHash)
		require.Empty(t, claims.Extra)
	}

	// Assert that the session headers are what we think they should be.
	headers := session.Headers
	require.Empty(t, headers)

	// Assert that the token expirations are what we think they should be.
	authCodeExpiresAt, ok := session.ExpiresAt[fosite.AuthorizeCode]
	require.True(t, ok, "expected session to hold expiration time for auth code")
	requireTimeInDelta(
		t,
		time.Now().UTC().Add(authCodeExpirationSeconds*time.Second),
		authCodeExpiresAt,
		timeComparisonFudgeSeconds*time.Second,
	)
	accessTokenExpiresAt, ok := session.ExpiresAt[fosite.AccessToken]
	require.True(t, ok, "expected session to hold expiration time for access token")
	requireTimeInDelta(
		t,
		time.Now().UTC().Add(accessTokenExpirationSeconds*time.Second),
		accessTokenExpiresAt,
		timeComparisonFudgeSeconds*time.Second,
	)

	// Assert that the session's username and subject are correct.
	require.Equal(t, goodUsername, session.Username)
	require.Equal(t, goodSubject, session.Subject)
}

// TODO: de-dup me.
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

// TODO: use actual testutil function.
//nolint:unparam
func requireTimeInDelta(t *testing.T, t1 time.Time, t2 time.Time, delta time.Duration) {
	t.Helper()
	require.InDeltaf(t,
		float64(t1.UnixNano()),
		float64(t2.UnixNano()),
		float64(delta.Nanoseconds()),
		"expected %s and %s to be < %s apart, but they are %s apart",
		t1.Format(time.RFC3339Nano),
		t2.Format(time.RFC3339Nano),
		delta.String(),
		t1.Sub(t2).String(),
	)
}

func deepCopyRequestForm(r *http.Request) *http.Request {
	copied := url.Values{}
	for k, v := range r.Form {
		copied[k] = v
	}
	return &http.Request{Form: copied}
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0)
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func contains(haystack []string, needle string) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}
