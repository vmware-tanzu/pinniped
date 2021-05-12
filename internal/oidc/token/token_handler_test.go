// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	josejwt "gopkg.in/square/go-jose.v2/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	storagepkce "go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/oidctestutil"
	"go.pinniped.dev/internal/testutil"
)

const (
	goodIssuer           = "https://some-issuer.com"
	goodClient           = "pinniped-cli"
	goodRedirectURI      = "http://127.0.0.1/callback"
	goodPKCECodeVerifier = "some-pkce-verifier-that-must-be-at-least-43-characters-to-meet-entropy-requirements"
	goodNonce            = "some-nonce-value-with-enough-bytes-to-exceed-min-allowed"
	goodSubject          = "https://issuer?sub=some-subject"
	goodUsername         = "some-username"
	goodGroups           = "group1,groups2"

	hmacSecret = "this needs to be at least 32 characters to meet entropy requirements"

	authCodeExpirationSeconds    = 10 * 60 // Current, we set our auth code expiration to 10 minutes
	accessTokenExpirationSeconds = 2 * 60  // Currently, we set our access token expiration to 2 minutes
	idTokenExpirationSeconds     = 2 * 60  // Currently, we set our ID token expiration to 2 minutes

	timeComparisonFudgeSeconds = 15
)

var (
	goodAuthTime        = time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC)
	goodRequestedAtTime = time.Date(7, 6, 5, 4, 3, 2, 1, time.UTC)

	hmacSecretFunc = func() []byte {
		return []byte(hmacSecret)
	}

	fositeInvalidMethodErrorBody = func(actual string) string {
		return here.Docf(`
			{
				"error":             "invalid_request",
				"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is '%s', expected 'POST'."
			 }
		`, actual)
	}

	fositeMissingGrantTypeErrorBody = here.Docf(`
		{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Request parameter 'grant_type' is missing"
		}
	`)

	fositeEmptyPayloadErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty."
		}
	`)

	fositeInvalidPayloadErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse HTTP body, make sure to send a properly formatted form request body."
		}
	`)

	fositeInvalidRequestErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."
		}
	`)

	fositeInvalidRequestMissingGrantTypeErrorBody = here.Doc(`
		{
		  "error": "invalid_request",
		  "error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Request parameter 'grant_type' is missing"
		}
	`)

	fositeMissingClientErrorBody = here.Doc(`
		{
			"error":             "invalid_request",
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client credentials missing or malformed in both HTTP Authorization header and HTTP POST body."
		}
	`)

	fositeInvalidClientErrorBody = here.Doc(`
		{
			"error":             "invalid_client",
			"error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
		}
	`)

	fositeInvalidAuthCodeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
		}
	`)

	fositeReusedAuthCodeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The authorization code has already been used."
		}
	`)

	fositeInvalidRedirectURIErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The 'redirect_uri' from this request does not match the one from the authorize request."
		}
	`)

	fositeMissingPKCEVerifierErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code verifier must be at least 43 characters."
		}
	`)

	fositeWrongPKCEVerifierErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier."
		}
	`)

	fositeTemporarilyUnavailableErrorBody = here.Doc(`
		{
		  "error": "temporarily_unavailable",
		  "error_description": "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
		}
	`)

	happyAuthRequest = &http.Request{
		Form: url.Values{
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"client_id":             {goodClient},
			"state":                 {"some-state-value-with-enough-bytes-to-exceed-min-allowed"},
			"nonce":                 {goodNonce},
			"code_challenge":        {testutil.SHA256(goodPKCECodeVerifier)},
			"code_challenge_method": {"S256"},
			"redirect_uri":          {goodRedirectURI},
		},
	}

	happyTokenExchangeRequest = func(audience string, subjectToken string) *http.Request {
		return &http.Request{
			Form: url.Values{
				"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"audience":             {audience},
				"subject_token":        {subjectToken},
				"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
				"requested_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
				"client_id":            {goodClient},
			},
		}
	}
)

type tokenEndpointResponseExpectedValues struct {
	wantStatus            int
	wantSuccessBodyFields []string
	wantErrorResponseBody string
	wantRequestedScopes   []string
	wantGrantedScopes     []string
}

type authcodeExchangeInputs struct {
	modifyAuthRequest  func(authRequest *http.Request)
	modifyTokenRequest func(tokenRequest *http.Request, authCode string)
	modifyStorage      func(
		t *testing.T,
		s interface {
			oauth2.TokenRevocationStorage
			oauth2.CoreStorage
			openid.OpenIDConnectRequestStorage
			pkce.PKCERequestStorage
			fosite.ClientManager
		},
		authCode string,
	)
	makeOathHelper func(
		t *testing.T,
		authRequest *http.Request,
		store interface {
			oauth2.TokenRevocationStorage
			oauth2.CoreStorage
			openid.OpenIDConnectRequestStorage
			pkce.PKCERequestStorage
			fosite.ClientManager
		},
	) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey)

	want tokenEndpointResponseExpectedValues
}

func TestTokenEndpoint(t *testing.T) {
	tests := []struct {
		name             string
		authcodeExchange authcodeExchangeInputs
	}{
		// happy path
		{
			name: "request is valid and tokens are issued",
			authcodeExchange: authcodeExchangeInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "profile", "email"},
					wantGrantedScopes:     []string{"openid"},
				},
			},
		},
		{
			name: "openid scope was not requested from authorize endpoint",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "profile email") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in"}, // no id or refresh tokens
					wantRequestedScopes:   []string{"profile", "email"},
					wantGrantedScopes:     []string{},
				},
			},
		},
		{
			name: "offline_access and openid scopes were requested and granted from authorize endpoint",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in", "refresh_token"}, // all possible tokens
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				},
			},
		},
		{
			name: "offline_access (without openid scope) was requested and granted from authorize endpoint",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in", "refresh_token"}, // no id token
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				},
			},
		},

		// sad path
		{
			name: "GET method is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Method = http.MethodGet },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidMethodErrorBody("GET"),
				},
			},
		},
		{
			name: "PUT method is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Method = http.MethodPut },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidMethodErrorBody("PUT"),
				},
			},
		},
		{
			name: "PATCH method is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Method = http.MethodPatch },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidMethodErrorBody("PATCH"),
				},
			},
		},
		{
			name: "DELETE method is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Method = http.MethodDelete },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidMethodErrorBody("DELETE"),
				},
			},
		},
		{
			name: "content type is invalid",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Header.Set("Content-Type", "text/plain") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeEmptyPayloadErrorBody,
				},
			},
		},
		{
			name: "payload is not valid form serialization",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = ioutil.NopCloser(strings.NewReader("this newline character is not allowed in a form serialization: \n"))
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeMissingGrantTypeErrorBody,
				},
			},
		},
		{
			name: "payload is empty",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) { r.Body = nil },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidPayloadErrorBody,
				},
			},
		},
		{
			name: "grant type is missing in request",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithGrantType("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeMissingGrantTypeErrorBody,
				},
			},
		},
		{
			name: "grant type is not authorization_code",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithGrantType("bogus").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRequestErrorBody,
				},
			},
		},
		{
			name: "client id is missing in request",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithClientID("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeMissingClientErrorBody,
				},
			},
		},
		{
			name: "client id is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithClientID("bogus").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeInvalidClientErrorBody,
				},
			},
		},
		{
			name: "grant type is missing",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithGrantType("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRequestMissingGrantTypeErrorBody,
				},
			},
		},
		{
			name: "grant type is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithGrantType("bogus").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRequestErrorBody,
				},
			},
		},
		{
			name: "auth code is missing in request",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithAuthCode("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				},
			},
		},
		{
			name: "auth code has never been valid",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithAuthCode("bogus").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				},
			},
		},
		{
			name: "redirect uri is missing in request",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithRedirectURI("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRedirectURIErrorBody,
				},
			},
		},
		{
			name: "redirect uri is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithRedirectURI("bogus").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRedirectURIErrorBody,
				},
			},
		},
		{
			name: "pkce is missing in request",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithPKCE("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeMissingPKCEVerifierErrorBody,
				},
			},
		},
		{
			name: "pkce is wrong",
			authcodeExchange: authcodeExchangeInputs{
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithPKCE(
						"bogus-verifier-that-is-at-least-43-characters-for-the-sake-of-entropy",
					).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeWrongPKCEVerifierErrorBody,
				},
			},
		},
		{
			name: "private signing key for JWTs has not yet been provided by the controller who is responsible for dynamically providing it",
			authcodeExchange: authcodeExchangeInputs{
				makeOathHelper: makeOauthHelperWithNilPrivateJWTSigningKey,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusServiceUnavailable,
					wantErrorResponseBody: fositeTemporarilyUnavailableErrorBody,
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			exchangeAuthcodeForTokens(t, test.authcodeExchange)
		})
	}
}

func TestTokenEndpointWhenAuthcodeIsUsedTwice(t *testing.T) {
	tests := []struct {
		name             string
		authcodeExchange authcodeExchangeInputs
	}{
		{
			name: "authcode exchange succeeds once and then fails when the same authcode is used again",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access profile email") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access", "profile", "email"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First call - should be successful.
			subject, rsp, authCode, _, secrets, oauthStore := exchangeAuthcodeForTokens(t, test.authcodeExchange)
			var parsedResponseBody map[string]interface{}
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedResponseBody))

			// Second call - should be unsuccessful since auth code was already used.
			//
			// Fosite will also revoke the access token as is recommended by the OIDC spec. Currently, we don't
			// delete the OIDC storage...but we probably should.
			req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyAuthcodeRequestBody(authCode).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reusedAuthcodeResponse := httptest.NewRecorder()
			subject.ServeHTTP(reusedAuthcodeResponse, req)
			t.Logf("second response: %#v", reusedAuthcodeResponse)
			t.Logf("second response body: %q", reusedAuthcodeResponse.Body.String())
			require.Equal(t, http.StatusBadRequest, reusedAuthcodeResponse.Code)
			testutil.RequireEqualContentType(t, reusedAuthcodeResponse.Header().Get("Content-Type"), "application/json")
			require.JSONEq(t, fositeReusedAuthCodeErrorBody, reusedAuthcodeResponse.Body.String())

			// This was previously invalidated by the first request, so it remains invalidated
			requireInvalidAuthCodeStorage(t, authCode, oauthStore, secrets)
			// Has now invalidated the access token that was previously handed out by the first request
			requireInvalidAccessTokenStorage(t, parsedResponseBody, oauthStore)
			// This was previously invalidated by the first request, so it remains invalidated
			requireInvalidPKCEStorage(t, authCode, oauthStore)
			// Fosite never cleans up OpenID Connect session storage, so it is still there
			requireValidOIDCStorage(t, parsedResponseBody, authCode, oauthStore,
				test.authcodeExchange.want.wantRequestedScopes, test.authcodeExchange.want.wantGrantedScopes)

			// Check that the access token and refresh token storage were both deleted, and the number of other storage objects did not change.
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 1)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: accesstoken.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: refreshtoken.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: storagepkce.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{}, 2)
		})
	}
}

func TestTokenExchange(t *testing.T) {
	successfulAuthCodeExchange := tokenEndpointResponseExpectedValues{
		wantStatus:            http.StatusOK,
		wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
		wantRequestedScopes:   []string{"openid", "pinniped:request-audience"},
		wantGrantedScopes:     []string{"openid", "pinniped:request-audience"},
	}

	doValidAuthCodeExchange := authcodeExchangeInputs{
		modifyAuthRequest: func(authRequest *http.Request) {
			authRequest.Form.Set("scope", "openid pinniped:request-audience")
		},
		want: successfulAuthCodeExchange,
	}
	tests := []struct {
		name string

		authcodeExchange    authcodeExchangeInputs
		modifyRequestParams func(t *testing.T, params url.Values)
		modifyStorage       func(t *testing.T, storage *oidc.KubeStorage, pendingRequest *http.Request)
		requestedAudience   string

		wantStatus               int
		wantResponseBodyContains string
	}{
		{
			name:              "happy path",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name:                     "missing audience",
			authcodeExchange:         doValidAuthCodeExchange,
			requestedAudience:        "",
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: "missing audience parameter",
		},
		{
			name:              "missing subject_token",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("subject_token")
			},
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: "missing subject_token parameter",
		},
		{
			name:              "wrong subject_token_type",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("subject_token_type", "invalid")
			},
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: `unsupported subject_token_type parameter value`,
		},
		{
			name:              "wrong requested_token_type",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("requested_token_type", "invalid")
			},
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: `unsupported requested_token_type parameter value`,
		},
		{
			name:              "unsupported RFC8693 parameter",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("resource", "some-resource-parameter-value")
			},
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: `unsupported parameter resource`,
		},
		{
			name:              "bogus access token",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("subject_token", "some-bogus-value")
			},
			wantStatus:               http.StatusBadRequest,
			wantResponseBodyContains: `Invalid token format`,
		},
		{
			name:              "valid access token, but deleted from storage",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyStorage: func(t *testing.T, storage *oidc.KubeStorage, pendingRequest *http.Request) {
				parts := strings.Split(pendingRequest.Form.Get("subject_token"), ".")
				require.Len(t, parts, 2)
				require.NoError(t, storage.DeleteAccessTokenSession(context.Background(), parts[1]))
			},
			wantStatus:               http.StatusUnauthorized,
			wantResponseBodyContains: `invalid subject_token`,
		},
		{
			name: "access token missing pinniped:request-audience scope",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid"},
					wantGrantedScopes:     []string{"openid"},
				},
			},
			requestedAudience:        "some-workload-cluster",
			wantStatus:               http.StatusForbidden,
			wantResponseBodyContains: `missing the 'pinniped:request-audience' scope`,
		},
		{
			name: "access token missing openid scope",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "pinniped:request-audience")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"pinniped:request-audience"},
					wantGrantedScopes:     []string{"pinniped:request-audience"},
				},
			},
			requestedAudience:        "some-workload-cluster",
			wantStatus:               http.StatusForbidden,
			wantResponseBodyContains: `missing the 'openid' scope`,
		},
		{
			name: "token minting failure",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid pinniped:request-audience")
				},
				// Fail to fetch a JWK signing key after the authcode exchange has happened.
				makeOathHelper: makeOauthHelperWithJWTKeyThatWorksOnlyOnce,
				want:           successfulAuthCodeExchange,
			},
			requestedAudience:        "some-workload-cluster",
			wantStatus:               http.StatusServiceUnavailable,
			wantResponseBodyContains: `The authorization server is currently unable to handle the request`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			subject, rsp, _, _, secrets, storage := exchangeAuthcodeForTokens(t, test.authcodeExchange)
			var parsedAuthcodeExchangeResponseBody map[string]interface{}
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedAuthcodeExchangeResponseBody))

			request := happyTokenExchangeRequest(test.requestedAudience, parsedAuthcodeExchangeResponseBody["access_token"].(string))
			if test.modifyStorage != nil {
				test.modifyStorage(t, storage, request)
			}
			if test.modifyRequestParams != nil {
				test.modifyRequestParams(t, request.Form)
			}

			req := httptest.NewRequest("POST", "/path/shouldn't/matter", body(request.Form).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rsp = httptest.NewRecorder()

			// Measure the secrets in storage after the auth code flow.
			existingSecrets, err := secrets.List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)

			// Wait one second before performing the token exchange so we can see that the new ID token has new issued
			// at and expires at dates which are newer than the old tokens.
			time.Sleep(1 * time.Second)

			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), "application/json")
			if test.wantResponseBodyContains != "" {
				require.Contains(t, rsp.Body.String(), test.wantResponseBodyContains)
			}

			// The remaining assertions apply only the the happy path.
			if rsp.Code != http.StatusOK {
				return
			}

			claimsOfFirstIDToken := map[string]interface{}{}
			originalIDToken := parsedAuthcodeExchangeResponseBody["id_token"].(string)
			firstIDTokenDecoded, _ := josejwt.ParseSigned(originalIDToken)
			err = firstIDTokenDecoded.UnsafeClaimsWithoutVerification(&claimsOfFirstIDToken)
			require.NoError(t, err)

			var responseBody map[string]interface{}
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &responseBody))

			require.Contains(t, responseBody, "access_token")
			require.Equal(t, "N_A", responseBody["token_type"])
			require.Equal(t, "urn:ietf:params:oauth:token-type:jwt", responseBody["issued_token_type"])

			// Parse the returned token.
			parsedJWT, err := jose.ParseSigned(responseBody["access_token"].(string))
			require.NoError(t, err)
			var tokenClaims map[string]interface{}
			require.NoError(t, json.Unmarshal(parsedJWT.UnsafePayloadWithoutVerification(), &tokenClaims))

			// Make sure that these are the only fields in the token.
			idTokenFields := []string{"sub", "aud", "iss", "jti", "nonce", "auth_time", "exp", "iat", "rat", "groups", "username"}
			require.ElementsMatch(t, idTokenFields, getMapKeys(tokenClaims))

			// Assert that the returned token has expected claims values.
			require.NotEmpty(t, tokenClaims["jti"])
			require.NotEmpty(t, tokenClaims["auth_time"])
			require.NotEmpty(t, tokenClaims["exp"])
			require.NotEmpty(t, tokenClaims["iat"])
			require.NotEmpty(t, tokenClaims["rat"])
			require.Empty(t, tokenClaims["nonce"]) // ID tokens only contain nonce during an authcode exchange
			require.Len(t, tokenClaims["aud"], 1)
			require.Contains(t, tokenClaims["aud"], test.requestedAudience)
			require.Equal(t, goodSubject, tokenClaims["sub"])
			require.Equal(t, goodIssuer, tokenClaims["iss"])
			require.Equal(t, goodUsername, tokenClaims["username"])
			require.Equal(t, goodGroups, tokenClaims["groups"])

			// Also assert that some are the same as the original downstream ID token.
			requireClaimsAreEqual(t, "iss", claimsOfFirstIDToken, tokenClaims)       // issuer
			requireClaimsAreEqual(t, "sub", claimsOfFirstIDToken, tokenClaims)       // subject
			requireClaimsAreEqual(t, "rat", claimsOfFirstIDToken, tokenClaims)       // requested at
			requireClaimsAreEqual(t, "auth_time", claimsOfFirstIDToken, tokenClaims) // auth time

			// Also assert which are the different from the original downstream ID token.
			requireClaimsAreNotEqual(t, "jti", claimsOfFirstIDToken, tokenClaims) // JWT ID
			requireClaimsAreNotEqual(t, "aud", claimsOfFirstIDToken, tokenClaims) // audience
			requireClaimsAreNotEqual(t, "exp", claimsOfFirstIDToken, tokenClaims) // expires at
			require.Greater(t, tokenClaims["exp"], claimsOfFirstIDToken["exp"])
			requireClaimsAreNotEqual(t, "iat", claimsOfFirstIDToken, tokenClaims) // issued at
			require.Greater(t, tokenClaims["iat"], claimsOfFirstIDToken["iat"])

			// Assert that nothing in storage has been modified.
			newSecrets, err := secrets.List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.ElementsMatch(t, existingSecrets.Items, newSecrets.Items)
		})
	}
}

type refreshRequestInputs struct {
	modifyTokenRequest func(tokenRequest *http.Request, refreshToken string, accessToken string)
	want               tokenEndpointResponseExpectedValues
}

func TestRefreshGrant(t *testing.T) {
	tests := []struct {
		name             string
		authcodeExchange authcodeExchangeInputs
		refreshRequest   refreshRequestInputs
	}{
		{
			name: "happy path refresh grant with ID token",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				}},
		},
		{
			name: "happy path refresh grant without ID token",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				}},
		},
		{
			name: "when the refresh request adds a new scope to the list of requested scopes then it is ignored",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid some-other-scope-not-from-auth-request").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				}},
		},
		{
			name: "when the refresh request removes a scope which was originally granted from the list of requested scopes then it is granted anyway",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access pinniped:request-audience") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGrantedScopes:     []string{"openid", "offline_access", "pinniped:request-audience"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid").ReadCloser() // do not ask for "pinniped:request-audience" again
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGrantedScopes:     []string{"openid", "offline_access", "pinniped:request-audience"},
				}},
		},
		{
			name: "when the refresh request does not include a scope param then it gets all the same scopes as the original authorization request",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
				}},
		},
		{
			name: "when a bad refresh token is sent in the refresh request",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken("bad refresh token").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				}},
		},
		{
			name: "when the access token is sent as if it were a refresh token",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken(accessToken).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				}},
		},
		{
			name: "when the wrong client ID is included in the refresh request",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithClientID("wrong-client-id").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeInvalidClientErrorBody,
				}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First exchange the authcode for tokens, including a refresh token.
			subject, rsp, authCode, jwtSigningKey, secrets, oauthStore := exchangeAuthcodeForTokens(t, test.authcodeExchange)
			var parsedAuthcodeExchangeResponseBody map[string]interface{}
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedAuthcodeExchangeResponseBody))

			// Wait one second before performing the refresh so we can see that the refreshed ID token has new issued
			// at and expires at dates which are newer than the old tokens.
			// If this gets too annoying in terms of making our test suite slower then we can remove it and adjust
			// the expectations about the ID token that are made at the end of this test accordingly.
			time.Sleep(1 * time.Second)

			// Send the refresh token back and preform a refresh.
			firstRefreshToken := parsedAuthcodeExchangeResponseBody["refresh_token"].(string)
			req := httptest.NewRequest("POST", "/path/shouldn't/matter",
				happyRefreshRequestBody(firstRefreshToken).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.refreshRequest.modifyTokenRequest != nil {
				test.refreshRequest.modifyTokenRequest(req, firstRefreshToken, parsedAuthcodeExchangeResponseBody["access_token"].(string))
			}

			refreshResponse := httptest.NewRecorder()
			subject.ServeHTTP(refreshResponse, req)
			t.Logf("second response: %#v", refreshResponse)
			t.Logf("second response body: %q", refreshResponse.Body.String())

			// The bug in fosite that prevents at_hash from appearing in the initial ID token does not impact the refreshed ID token
			wantAtHashClaimInIDToken := true
			// Refreshed ID tokens do not include the nonce from the original auth request
			wantNonceValueInIDToken := false
			requireTokenEndpointBehavior(t, test.refreshRequest.want, wantAtHashClaimInIDToken, wantNonceValueInIDToken, refreshResponse, authCode, oauthStore, jwtSigningKey, secrets)

			if test.refreshRequest.want.wantStatus == http.StatusOK {
				wantIDToken := contains(test.refreshRequest.want.wantSuccessBodyFields, "id_token")

				var parsedRefreshResponseBody map[string]interface{}
				require.NoError(t, json.Unmarshal(refreshResponse.Body.Bytes(), &parsedRefreshResponseBody))

				// Check that we got back new tokens.
				require.NotEqual(t, parsedAuthcodeExchangeResponseBody["access_token"].(string), parsedRefreshResponseBody["access_token"].(string))
				require.NotEqual(t, parsedAuthcodeExchangeResponseBody["refresh_token"].(string), parsedRefreshResponseBody["refresh_token"].(string))
				if wantIDToken {
					require.NotEqual(t, parsedAuthcodeExchangeResponseBody["id_token"].(string), parsedRefreshResponseBody["id_token"].(string))
				}

				// The other fields of the response should be the same as the original response. Note that expires_in is a number of seconds from now.
				require.Equal(t, parsedAuthcodeExchangeResponseBody["token_type"].(string), parsedRefreshResponseBody["token_type"].(string))
				require.InDelta(t, parsedAuthcodeExchangeResponseBody["expires_in"].(float64), parsedRefreshResponseBody["expires_in"].(float64), 2)
				require.Equal(t, parsedAuthcodeExchangeResponseBody["scope"].(string), parsedRefreshResponseBody["scope"].(string))

				if wantIDToken {
					var claimsOfFirstIDToken map[string]interface{}
					firstIDTokenDecoded, _ := josejwt.ParseSigned(parsedAuthcodeExchangeResponseBody["id_token"].(string))
					err := firstIDTokenDecoded.UnsafeClaimsWithoutVerification(&claimsOfFirstIDToken)
					require.NoError(t, err)

					var claimsOfSecondIDToken map[string]interface{}
					secondIDTokenDecoded, _ := josejwt.ParseSigned(parsedRefreshResponseBody["id_token"].(string))
					err = secondIDTokenDecoded.UnsafeClaimsWithoutVerification(&claimsOfSecondIDToken)
					require.NoError(t, err)

					requireClaimsAreNotEqual(t, "jti", claimsOfFirstIDToken, claimsOfSecondIDToken) // JWT ID
					requireClaimsAreNotEqual(t, "exp", claimsOfFirstIDToken, claimsOfSecondIDToken) // expires at
					require.Greater(t, claimsOfSecondIDToken["exp"], claimsOfFirstIDToken["exp"])
					requireClaimsAreNotEqual(t, "iat", claimsOfFirstIDToken, claimsOfSecondIDToken) // issued at
					require.Greater(t, claimsOfSecondIDToken["iat"], claimsOfFirstIDToken["iat"])

					requireClaimsAreEqual(t, "iss", claimsOfFirstIDToken, claimsOfSecondIDToken)       // issuer
					requireClaimsAreEqual(t, "aud", claimsOfFirstIDToken, claimsOfSecondIDToken)       // audience
					requireClaimsAreEqual(t, "sub", claimsOfFirstIDToken, claimsOfSecondIDToken)       // subject
					requireClaimsAreEqual(t, "rat", claimsOfFirstIDToken, claimsOfSecondIDToken)       // requested at
					requireClaimsAreEqual(t, "auth_time", claimsOfFirstIDToken, claimsOfSecondIDToken) // auth time
				}
			}
		})
	}
}

func requireClaimsAreNotEqual(t *testing.T, claimName string, claimsOfTokenA map[string]interface{}, claimsOfTokenB map[string]interface{}) {
	require.NotEmpty(t, claimsOfTokenA[claimName])
	require.NotEmpty(t, claimsOfTokenB[claimName])
	require.NotEqual(t, claimsOfTokenA[claimName], claimsOfTokenB[claimName])
}

func requireClaimsAreEqual(t *testing.T, claimName string, claimsOfTokenA map[string]interface{}, claimsOfTokenB map[string]interface{}) {
	require.NotEmpty(t, claimsOfTokenA[claimName])
	require.NotEmpty(t, claimsOfTokenB[claimName])
	require.Equal(t, claimsOfTokenA[claimName], claimsOfTokenB[claimName])
}

func exchangeAuthcodeForTokens(t *testing.T, test authcodeExchangeInputs) (
	subject http.Handler,
	rsp *httptest.ResponseRecorder,
	authCode string,
	jwtSigningKey *ecdsa.PrivateKey,
	secrets v1.SecretInterface,
	oauthStore *oidc.KubeStorage,
) {
	authRequest := deepCopyRequestForm(happyAuthRequest)
	if test.modifyAuthRequest != nil {
		test.modifyAuthRequest(authRequest)
	}

	client := fake.NewSimpleClientset()
	secrets = client.CoreV1().Secrets("some-namespace")

	var oauthHelper fosite.OAuth2Provider

	oauthStore = oidc.NewKubeStorage(secrets, oidc.DefaultOIDCTimeoutsConfiguration())
	if test.makeOathHelper != nil {
		oauthHelper, authCode, jwtSigningKey = test.makeOathHelper(t, authRequest, oauthStore)
	} else {
		oauthHelper, authCode, jwtSigningKey = makeHappyOauthHelper(t, authRequest, oauthStore)
	}

	if test.modifyStorage != nil {
		test.modifyStorage(t, oauthStore, authCode)
	}
	subject = NewHandler(oauthHelper)

	authorizeEndpointGrantedOpenIDScope := strings.Contains(authRequest.Form.Get("scope"), "openid")
	expectedNumberOfIDSessionsStored := 0
	if authorizeEndpointGrantedOpenIDScope {
		expectedNumberOfIDSessionsStored = 1
	}

	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: storagepkce.TypeLabelValue}, 1)
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, expectedNumberOfIDSessionsStored)
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{}, 2+expectedNumberOfIDSessionsStored)

	req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyAuthcodeRequestBody(authCode).ReadCloser())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if test.modifyTokenRequest != nil {
		test.modifyTokenRequest(req, authCode)
	}
	rsp = httptest.NewRecorder()

	subject.ServeHTTP(rsp, req)
	t.Logf("response: %#v", rsp)
	t.Logf("response body: %q", rsp.Body.String())

	wantAtHashClaimInIDToken := false // due to a bug in fosite, the at_hash claim is not filled in during authcode exchange
	wantNonceValueInIDToken := true   // ID tokens returned by the authcode exchange must include the nonce from the auth request (unliked refreshed ID tokens)
	requireTokenEndpointBehavior(t, test.want, wantAtHashClaimInIDToken, wantNonceValueInIDToken, rsp, authCode, oauthStore, jwtSigningKey, secrets)

	return subject, rsp, authCode, jwtSigningKey, secrets, oauthStore
}

func requireTokenEndpointBehavior(
	t *testing.T,
	test tokenEndpointResponseExpectedValues,
	wantAtHashClaimInIDToken bool,
	wantNonceValueInIDToken bool,
	tokenEndpointResponse *httptest.ResponseRecorder,
	authCode string,
	oauthStore *oidc.KubeStorage,
	jwtSigningKey *ecdsa.PrivateKey,
	secrets v1.SecretInterface,
) {
	testutil.RequireEqualContentType(t, tokenEndpointResponse.Header().Get("Content-Type"), "application/json")
	require.Equal(t, test.wantStatus, tokenEndpointResponse.Code)

	if test.wantStatus == http.StatusOK {
		require.NotNil(t, test.wantSuccessBodyFields, "problem with test table setup: wanted success but did not specify expected response body")

		var parsedResponseBody map[string]interface{}
		require.NoError(t, json.Unmarshal(tokenEndpointResponse.Body.Bytes(), &parsedResponseBody))
		require.ElementsMatch(t, test.wantSuccessBodyFields, getMapKeys(parsedResponseBody))

		wantIDToken := contains(test.wantSuccessBodyFields, "id_token")
		wantRefreshToken := contains(test.wantSuccessBodyFields, "refresh_token")

		requireInvalidAuthCodeStorage(t, authCode, oauthStore, secrets)
		requireValidAccessTokenStorage(t, parsedResponseBody, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes, secrets)
		requireInvalidPKCEStorage(t, authCode, oauthStore)
		requireValidOIDCStorage(t, parsedResponseBody, authCode, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes)

		expectedNumberOfRefreshTokenSessionsStored := 0
		if wantRefreshToken {
			expectedNumberOfRefreshTokenSessionsStored = 1
		}
		expectedNumberOfIDSessionsStored := 0
		if wantIDToken {
			expectedNumberOfIDSessionsStored = 1
			requireValidIDToken(t, parsedResponseBody, jwtSigningKey, wantAtHashClaimInIDToken, wantNonceValueInIDToken, parsedResponseBody["access_token"].(string))
		}
		if wantRefreshToken {
			requireValidRefreshTokenStorage(t, parsedResponseBody, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes, secrets)
		}

		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: accesstoken.TypeLabelValue}, 1)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: storagepkce.TypeLabelValue}, 0)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: refreshtoken.TypeLabelValue}, expectedNumberOfRefreshTokenSessionsStored)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, expectedNumberOfIDSessionsStored)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{}, 2+expectedNumberOfRefreshTokenSessionsStored+expectedNumberOfIDSessionsStored)
	} else {
		require.NotNil(t, test.wantErrorResponseBody, "problem with test table setup: wanted failure but did not specify failure response body")

		require.JSONEq(t, test.wantErrorResponseBody, tokenEndpointResponse.Body.String())
	}
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

type body url.Values

func happyAuthcodeRequestBody(happyAuthCode string) body {
	return map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {happyAuthCode},
		"redirect_uri":  {goodRedirectURI},
		"code_verifier": {goodPKCECodeVerifier},
		"client_id":     {goodClient},
	}
}

func happyRefreshRequestBody(refreshToken string) body {
	return map[string][]string{
		"grant_type":    {"refresh_token"},
		"scope":         {"openid"},
		"client_id":     {goodClient},
		"refresh_token": {refreshToken},
	}
}

func (b body) WithGrantType(grantType string) body {
	return b.with("grant_type", grantType)
}

func (b body) WithRefreshToken(refreshToken string) body {
	return b.with("refresh_token", refreshToken)
}

func (b body) WithClientID(clientID string) body {
	return b.with("client_id", clientID)
}

func (b body) WithAuthCode(code string) body {
	return b.with("code", code)
}

func (b body) WithScope(scope string) body {
	return b.with("scope", scope)
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
	store interface {
		oauth2.TokenRevocationStorage
		oauth2.CoreStorage
		openid.OpenIDConnectRequestStorage
		pkce.PKCERequestStorage
		fosite.ClientManager
	},
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwtSigningKey, jwkProvider := generateJWTSigningKeyAndJWKSProvider(t, goodIssuer)
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, jwkProvider, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper)
	return oauthHelper, authResponder.GetCode(), jwtSigningKey
}

type singleUseJWKProvider struct {
	jwks.DynamicJWKSProvider
	calls int
}

func (s *singleUseJWKProvider) GetJWKS(issuerName string) (jwks *jose.JSONWebKeySet, activeJWK *jose.JSONWebKey) {
	s.calls++
	if s.calls > 1 {
		return nil, nil
	}
	return s.DynamicJWKSProvider.GetJWKS(issuerName)
}

func makeOauthHelperWithJWTKeyThatWorksOnlyOnce(
	t *testing.T,
	authRequest *http.Request,
	store interface {
		oauth2.TokenRevocationStorage
		oauth2.CoreStorage
		openid.OpenIDConnectRequestStorage
		pkce.PKCERequestStorage
		fosite.ClientManager
	},
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwtSigningKey, jwkProvider := generateJWTSigningKeyAndJWKSProvider(t, goodIssuer)
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, &singleUseJWKProvider{DynamicJWKSProvider: jwkProvider}, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper)
	return oauthHelper, authResponder.GetCode(), jwtSigningKey
}

func makeOauthHelperWithNilPrivateJWTSigningKey(
	t *testing.T,
	authRequest *http.Request,
	store interface {
		oauth2.TokenRevocationStorage
		oauth2.CoreStorage
		openid.OpenIDConnectRequestStorage
		pkce.PKCERequestStorage
		fosite.ClientManager
	},
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwkProvider := jwks.NewDynamicJWKSProvider() // empty provider which contains no signing key for this issuer
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, jwkProvider, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper)
	return oauthHelper, authResponder.GetCode(), nil
}

// Simulate the auth endpoint running so Fosite code will fill the store with realistic values.
func simulateAuthEndpointHavingAlreadyRun(t *testing.T, authRequest *http.Request, oauthHelper fosite.OAuth2Provider) fosite.AuthorizeResponder {
	// We only set the fields in the session that Fosite wants us to set.
	ctx := context.Background()
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     goodSubject,
			RequestedAt: goodRequestedAtTime,
			AuthTime:    goodAuthTime,
			Extra: map[string]interface{}{
				oidc.DownstreamUsernameClaim: goodUsername,
				oidc.DownstreamGroupsClaim:   goodGroups,
			},
		},
		Subject:  "", // not used, note that callback_handler.go does not set this
		Username: "", // not used, note that callback_handler.go does not set this
	}
	authRequester, err := oauthHelper.NewAuthorizeRequest(ctx, authRequest)
	require.NoError(t, err)
	if strings.Contains(authRequest.Form.Get("scope"), "openid") {
		authRequester.GrantScope("openid")
	}
	if strings.Contains(authRequest.Form.Get("scope"), "offline_access") {
		authRequester.GrantScope("offline_access")
	}
	if strings.Contains(authRequest.Form.Get("scope"), "pinniped:request-audience") {
		authRequester.GrantScope("pinniped:request-audience")
	}
	authResponder, err := oauthHelper.NewAuthorizeResponse(ctx, authRequester, session)
	require.NoError(t, err)
	return authResponder
}

func generateJWTSigningKeyAndJWKSProvider(t *testing.T, issuer string) (*ecdsa.PrivateKey, jwks.DynamicJWKSProvider) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwksProvider := jwks.NewDynamicJWKSProvider()
	jwksProvider.SetIssuerToJWKSMap(
		nil, // public JWKS unused
		map[string]*jose.JSONWebKey{
			issuer: {Key: key},
		},
	)

	return key, jwksProvider
}

func requireInvalidAuthCodeStorage(
	t *testing.T,
	code string,
	storage oauth2.CoreStorage,
	secrets v1.SecretInterface,
) {
	t.Helper()

	// Make sure we have invalidated this auth code.
	_, err := storage.GetAuthorizeCodeSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.True(t, errors.Is(err, fosite.ErrInvalidatedAuthorizeCode))
	// make sure that its still around in storage so if someone tries to use it again we invalidate everything
	requireGarbageCollectTimeInDelta(t, code, "authcode", secrets, time.Now().Add(9*time.Hour).Add(10*time.Minute), 30*time.Second)
}

func requireValidRefreshTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage oauth2.CoreStorage,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	secrets v1.SecretInterface,
) {
	t.Helper()

	// Get the refresh token, and make sure we can use it to perform a lookup on the storage.
	refreshToken, ok := body["refresh_token"]
	require.True(t, ok)
	refreshTokenString, ok := refreshToken.(string)
	require.Truef(t, ok, "wanted refresh_token to be a string, but got %T", refreshToken)
	require.NotEmpty(t, refreshTokenString)
	storedRequest, err := storage.GetRefreshTokenSession(context.Background(), getFositeDataSignature(t, refreshTokenString), nil)
	require.NoError(t, err)

	// Fosite stores refresh tokens without any of the original request form parameters.
	requireValidStoredRequest(
		t,
		storedRequest,
		storedRequest.Sanitize([]string{}).GetRequestForm(),
		wantRequestedScopes,
		wantGrantedScopes,
		true,
	)

	requireGarbageCollectTimeInDelta(t, refreshTokenString, "refresh-token", secrets, time.Now().Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireValidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage oauth2.CoreStorage,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	secrets v1.SecretInterface,
) {
	t.Helper()

	// Get the access token, and make sure we can use it to perform a lookup on the storage.
	accessToken, ok := body["access_token"]
	require.True(t, ok)
	accessTokenString, ok := accessToken.(string)
	require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
	require.NotEmpty(t, accessTokenString)
	storedRequest, err := storage.GetAccessTokenSession(context.Background(), getFositeDataSignature(t, accessTokenString), nil)
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
	require.InDelta(t, accessTokenExpirationSeconds, expiresInNumber, 2) // "expires_in" is a number of seconds, not a timestamp

	scopes, ok := body["scope"]
	require.True(t, ok)
	actualGrantedScopesString, ok := scopes.(string)
	require.Truef(t, ok, "wanted scopes to be an string, but got %T", scopes)
	require.Equal(t, strings.Join(wantGrantedScopes, " "), actualGrantedScopesString)

	// Fosite stores access tokens without any of the original request form parameters.
	requireValidStoredRequest(
		t,
		storedRequest,
		storedRequest.Sanitize([]string{}).GetRequestForm(),
		wantRequestedScopes,
		wantGrantedScopes,
		true,
	)

	requireGarbageCollectTimeInDelta(t, accessTokenString, "access-token", secrets, time.Now().Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireInvalidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage oauth2.CoreStorage,
) {
	t.Helper()

	// Get the access token, and make sure we can use it to perform a lookup on the storage.
	accessToken, ok := body["access_token"]
	require.True(t, ok)
	accessTokenString, ok := accessToken.(string)
	require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
	_, err := storage.GetAccessTokenSession(context.Background(), getFositeDataSignature(t, accessTokenString), nil)
	require.True(t, errors.Is(err, fosite.ErrNotFound))
}

func requireInvalidPKCEStorage(
	t *testing.T,
	code string,
	storage pkce.PKCERequestStorage,
) {
	t.Helper()

	// Make sure the PKCE session has been deleted. Note that Fosite stores PKCE codes using the auth code signature
	// as a key.
	_, err := storage.GetPKCERequestSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.True(t, errors.Is(err, fosite.ErrNotFound))
}

func requireValidOIDCStorage(
	t *testing.T,
	body map[string]interface{},
	code string,
	storage openid.OpenIDConnectRequestStorage,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
) {
	t.Helper()

	if contains(wantGrantedScopes, "openid") {
		// Make sure the OIDC session is still there. Note that Fosite stores OIDC sessions using the full auth code as a key.
		storedRequest, err := storage.GetOpenIDConnectSession(context.Background(), code, nil)
		require.NoError(t, err)

		// Fosite stores OIDC sessions with only the nonce in the original request form.
		accessToken, ok := body["access_token"]
		require.True(t, ok)
		accessTokenString, ok := accessToken.(string)
		require.Truef(t, ok, "wanted access_token to be a string, but got %T", accessToken)
		require.NotEmpty(t, accessTokenString)

		requireValidStoredRequest(
			t,
			storedRequest,
			storedRequest.Sanitize([]string{"nonce"}).GetRequestForm(),
			wantRequestedScopes,
			wantGrantedScopes,
			false,
		)
	} else {
		_, err := storage.GetOpenIDConnectSession(context.Background(), code, nil)
		require.True(t, errors.Is(err, fosite.ErrNotFound))
	}
}

func requireValidStoredRequest(
	t *testing.T,
	request fosite.Requester,
	wantRequestForm url.Values,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantAccessTokenExpiresAt bool,
) {
	t.Helper()

	// Assert that the getters on the request return what we think they should.
	require.NotEmpty(t, request.GetID())
	testutil.RequireTimeInDelta(t, request.GetRequestedAt(), time.Now().UTC(), timeComparisonFudgeSeconds*time.Second)
	require.Equal(t, goodClient, request.GetClient().GetID())
	require.Equal(t, fosite.Arguments(wantRequestedScopes), request.GetRequestedScopes())
	require.Equal(t, fosite.Arguments(wantGrantedScopes), request.GetGrantedScopes())
	require.Empty(t, request.GetRequestedAudience())
	require.Empty(t, request.GetGrantedAudience())
	require.Equal(t, wantRequestForm, request.GetRequestForm()) // Fosite stores access token request without form

	// Cast session to the type we think it should be.
	session, ok := request.GetSession().(*openid.DefaultSession)
	require.Truef(t, ok, "could not cast %T to %T", request.GetSession(), &openid.DefaultSession{})

	// Assert that the session claims are what we think they should be, but only if we are doing OIDC.
	if contains(wantGrantedScopes, "openid") {
		claims := session.Claims
		require.Empty(t, claims.JTI) // When claims.JTI is empty, Fosite will generate a UUID for this field.
		require.Equal(t, goodSubject, claims.Subject)

		// Our custom claims from the authorize endpoint should still be set.
		require.Equal(t, map[string]interface{}{
			"username": goodUsername,
			"groups":   goodGroups,
		}, claims.Extra)

		// We are in charge of setting these fields. For the purpose of testing, we ensure that the
		// sentinel test value is set correctly.
		require.Equal(t, goodRequestedAtTime, claims.RequestedAt)
		require.Equal(t, goodAuthTime, claims.AuthTime)

		// These fields will all be given good defaults by fosite at runtime and we only need to use them
		// if we want to override the default behaviors. We currently don't need to override these defaults,
		// so they do not end up being stored. Fosite sets its defaults at runtime in openid.DefaultSession's
		// GenerateIDToken() method.
		require.Empty(t, claims.Issuer)
		require.Empty(t, claims.Audience)
		require.Empty(t, claims.Nonce)
		require.Zero(t, claims.ExpiresAt)
		require.Zero(t, claims.IssuedAt)

		// Fosite unconditionally overwrites claims.AccessTokenHash at runtime in openid.OpenIDConnectExplicitHandler's
		// PopulateTokenEndpointResponse() method, just before it calls the same GenerateIDToken() mentioned above,
		// so it does not end up saved in storage.
		require.Empty(t, claims.AccessTokenHash)

		// At this time, we don't use any of these optional (per the OIDC spec) fields.
		require.Empty(t, claims.AuthenticationContextClassReference)
		require.Empty(t, claims.AuthenticationMethodsReference)
		require.Empty(t, claims.CodeHash)
	}

	// Assert that the session headers are what we think they should be.
	headers := session.Headers
	require.Empty(t, headers)

	// Assert that the token expirations are what we think they should be.
	authCodeExpiresAt, ok := session.ExpiresAt[fosite.AuthorizeCode]
	require.True(t, ok, "expected session to hold expiration time for auth code")
	testutil.RequireTimeInDelta(
		t,
		time.Now().UTC().Add(authCodeExpirationSeconds*time.Second),
		authCodeExpiresAt,
		timeComparisonFudgeSeconds*time.Second,
	)

	// OpenID Connect sessions do not store access token expiration information.
	accessTokenExpiresAt, ok := session.ExpiresAt[fosite.AccessToken]
	if wantAccessTokenExpiresAt {
		require.True(t, ok, "expected session to hold expiration time for access token")
		testutil.RequireTimeInDelta(
			t,
			time.Now().UTC().Add(accessTokenExpirationSeconds*time.Second),
			accessTokenExpiresAt,
			timeComparisonFudgeSeconds*time.Second,
		)
	} else {
		require.False(t, ok, "expected session to not hold expiration time for access token, but it did")
	}

	// We don't use these, so they should be empty.
	require.Empty(t, session.Username)
	require.Empty(t, session.Subject)
}

func requireGarbageCollectTimeInDelta(t *testing.T, tokenString string, typeLabel string, secrets v1.SecretInterface, wantExpirationTime time.Time, deltaTime time.Duration) {
	t.Helper()
	signature := getFositeDataSignature(t, tokenString)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	require.NoError(t, err)
	// lower case base32 encoding insures that our secret name is valid per ValidateSecretName in k/k
	var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	signatureAsValidName := strings.ToLower(b32.EncodeToString(signatureBytes))
	secretName := fmt.Sprintf("pinniped-storage-%s-%s", typeLabel, signatureAsValidName)
	secret, err := secrets.Get(context.Background(), secretName, metav1.GetOptions{})
	require.NoError(t, err)
	refreshTokenGCTimeString := secret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	refreshTokenGCTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, refreshTokenGCTimeString)
	require.NoError(t, err)

	testutil.RequireTimeInDelta(t, refreshTokenGCTime, wantExpirationTime, deltaTime)
}

func requireValidIDToken(
	t *testing.T,
	body map[string]interface{},
	jwtSigningKey *ecdsa.PrivateKey,
	wantAtHashClaimInIDToken bool,
	wantNonceValueInIDToken bool,
	actualAccessToken string,
) {
	t.Helper()

	idToken, ok := body["id_token"]
	require.Truef(t, ok, "body did not contain 'id_token': %s", body)
	idTokenString, ok := idToken.(string)
	require.Truef(t, ok, "wanted id_token to be a string, but got %T", idToken)

	// The go-oidc library will validate the signature and the client claim in the ID token.
	token := oidctestutil.VerifyECDSAIDToken(t, goodIssuer, goodClient, jwtSigningKey, idTokenString)

	var claims struct {
		Subject         string   `json:"sub"`
		Audience        []string `json:"aud"`
		Issuer          string   `json:"iss"`
		JTI             string   `json:"jti"`
		Nonce           string   `json:"nonce"`
		AccessTokenHash string   `json:"at_hash"`
		ExpiresAt       int64    `json:"exp"`
		IssuedAt        int64    `json:"iat"`
		RequestedAt     int64    `json:"rat"`
		AuthTime        int64    `json:"auth_time"`
		Groups          string   `json:"groups"`
		Username        string   `json:"username"`
	}

	// Note that there is a bug in fosite which prevents the `at_hash` claim from appearing in this ID token
	// during the initial authcode exchange, but does not prevent `at_hash` from appearing in the refreshed ID token.
	// We can add a workaround for this later.
	idTokenFields := []string{"sub", "aud", "iss", "jti", "nonce", "auth_time", "exp", "iat", "rat", "groups", "username"}
	if wantAtHashClaimInIDToken {
		idTokenFields = append(idTokenFields, "at_hash")
	}

	// make sure that these are the only fields in the token
	var m map[string]interface{}
	require.NoError(t, token.Claims(&m))
	require.ElementsMatch(t, idTokenFields, getMapKeys(m))

	// verify each of the claims
	err := token.Claims(&claims)
	require.NoError(t, err)
	require.Equal(t, goodSubject, claims.Subject)
	require.Equal(t, goodUsername, claims.Username)
	require.Equal(t, goodGroups, claims.Groups)
	require.Len(t, claims.Audience, 1)
	require.Equal(t, goodClient, claims.Audience[0])
	require.Equal(t, goodIssuer, claims.Issuer)
	require.NotEmpty(t, claims.JTI)

	if wantNonceValueInIDToken {
		require.Equal(t, goodNonce, claims.Nonce)
	} else {
		require.Empty(t, claims.Nonce)
	}

	expiresAt := time.Unix(claims.ExpiresAt, 0)
	issuedAt := time.Unix(claims.IssuedAt, 0)
	requestedAt := time.Unix(claims.RequestedAt, 0)
	authTime := time.Unix(claims.AuthTime, 0)
	testutil.RequireTimeInDelta(t, time.Now().UTC().Add(idTokenExpirationSeconds*time.Second), expiresAt, timeComparisonFudgeSeconds*time.Second)
	testutil.RequireTimeInDelta(t, time.Now().UTC(), issuedAt, timeComparisonFudgeSeconds*time.Second)
	testutil.RequireTimeInDelta(t, goodRequestedAtTime, requestedAt, timeComparisonFudgeSeconds*time.Second)
	testutil.RequireTimeInDelta(t, goodAuthTime, authTime, timeComparisonFudgeSeconds*time.Second)

	if wantAtHashClaimInIDToken {
		require.NotEmpty(t, actualAccessToken)
		require.Equal(t, hashAccessToken(actualAccessToken), claims.AccessTokenHash)
	} else {
		require.Empty(t, claims.AccessTokenHash)
	}
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
