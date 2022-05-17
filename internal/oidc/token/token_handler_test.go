// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
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
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
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
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

const (
	goodIssuer           = "https://some-issuer.com"
	goodUpstreamSubject  = "some-subject"
	goodClient           = "pinniped-cli"
	goodRedirectURI      = "http://127.0.0.1/callback"
	goodPKCECodeVerifier = "some-pkce-verifier-that-must-be-at-least-43-characters-to-meet-entropy-requirements"
	goodNonce            = "some-nonce-value-with-enough-bytes-to-exceed-min-allowed"
	goodSubject          = "https://issuer?sub=some-subject"
	goodUsername         = "some-username"

	hmacSecret = "this needs to be at least 32 characters to meet entropy requirements"

	authCodeExpirationSeconds    = 10 * 60 // Current, we set our auth code expiration to 10 minutes
	accessTokenExpirationSeconds = 2 * 60  // Currently, we set our access token expiration to 2 minutes
	idTokenExpirationSeconds     = 2 * 60  // Currently, we set our ID token expiration to 2 minutes

	timeComparisonFudgeSeconds = 15
)

var (
	goodAuthTime        = time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC)
	goodRequestedAtTime = time.Date(7, 6, 5, 4, 3, 2, 1, time.UTC)
	goodGroups          = []string{"group1", "groups2"} // the default groups set by the authorize endpoint for these tests

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
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty."
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

	pinnipedUpstreamSessionDataNotFoundErrorBody = here.Doc(`
		{
			"error":             "error",
			"error_description": "There was an internal server error. Required upstream data not found in session."
		}
	`)

	fositeUpstreamGroupClaimErrorBody = here.Doc(`
		{
			"error":             "error",
			"error_description": "Error during upstream refresh. Upstream refresh error while extracting groups claim."
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

type expectedUpstreamRefresh struct {
	performedByUpstreamName string
	args                    *oidctestutil.PerformRefreshArgs
}

type expectedUpstreamValidateTokens struct {
	performedByUpstreamName string
	args                    *oidctestutil.ValidateTokenAndMergeWithUserInfoArgs
}

type tokenEndpointResponseExpectedValues struct {
	wantStatus                        int
	wantSuccessBodyFields             []string
	wantErrorResponseBody             string
	wantRequestedScopes               []string
	wantGrantedScopes                 []string
	wantGroups                        []string
	wantUpstreamRefreshCall           *expectedUpstreamRefresh
	wantUpstreamOIDCValidateTokenCall *expectedUpstreamValidateTokens
	wantCustomSessionDataStored       *psession.CustomSessionData
}

type authcodeExchangeInputs struct {
	modifyAuthRequest  func(authRequest *http.Request)
	modifyTokenRequest func(tokenRequest *http.Request, authCode string)
	modifyStorage      func(
		t *testing.T,
		s fositestoragei.AllFositeStorage,
		authCode string,
	)
	makeOathHelper    OauthHelperFactoryFunc
	customSessionData *psession.CustomSessionData
	want              tokenEndpointResponseExpectedValues
}

func TestTokenEndpointAuthcodeExchange(t *testing.T) {
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
					wantGroups:            goodGroups,
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
					wantGroups:            goodGroups,
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
					wantGroups:            goodGroups,
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
					wantGroups:            goodGroups,
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

			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			exchangeAuthcodeForTokens(t, test.authcodeExchange, oidctestutil.NewUpstreamIDPListerBuilder().Build())
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
					wantGroups:            goodGroups,
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First call - should be successful.
			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			subject, rsp, authCode, _, secrets, oauthStore := exchangeAuthcodeForTokens(t,
				test.authcodeExchange, oidctestutil.NewUpstreamIDPListerBuilder().Build())
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
			// Fosite never cleans up OpenID Connect session storage, so it is still there.
			// Note that customSessionData is only relevant to refresh grant, so we leave it as nil for this
			// authcode exchange test, even though in practice it would actually be in the session.
			requireValidOIDCStorage(t, parsedResponseBody, authCode, oauthStore,
				test.authcodeExchange.want.wantRequestedScopes, test.authcodeExchange.want.wantGrantedScopes, test.authcodeExchange.want.wantGroups, nil)

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

func TestTokenEndpointTokenExchange(t *testing.T) { // tests for grant_type "urn:ietf:params:oauth:grant-type:token-exchange"
	successfulAuthCodeExchange := tokenEndpointResponseExpectedValues{
		wantStatus:            http.StatusOK,
		wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
		wantRequestedScopes:   []string{"openid", "pinniped:request-audience"},
		wantGrantedScopes:     []string{"openid", "pinniped:request-audience"},
		wantGroups:            goodGroups,
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
					wantGroups:            goodGroups,
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
					wantGroups:            goodGroups,
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

			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			subject, rsp, _, _, secrets, storage := exchangeAuthcodeForTokens(t,
				test.authcodeExchange, oidctestutil.NewUpstreamIDPListerBuilder().Build())
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

			// The remaining assertions apply only to the happy path.
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
			idTokenFields := []string{"sub", "aud", "iss", "jti", "auth_time", "exp", "iat", "rat", "groups", "username"}
			require.ElementsMatch(t, idTokenFields, getMapKeys(tokenClaims))

			// Assert that the returned token has expected claims values.
			require.NotEmpty(t, tokenClaims["jti"])
			require.NotEmpty(t, tokenClaims["auth_time"])
			require.NotEmpty(t, tokenClaims["exp"])
			require.NotEmpty(t, tokenClaims["iat"])
			require.NotEmpty(t, tokenClaims["rat"])
			require.Len(t, tokenClaims["aud"], 1)
			require.Contains(t, tokenClaims["aud"], test.requestedAudience)
			require.Equal(t, goodSubject, tokenClaims["sub"])
			require.Equal(t, goodIssuer, tokenClaims["iss"])
			require.Equal(t, goodUsername, tokenClaims["username"])
			require.Equal(t, toSliceOfInterface(test.authcodeExchange.want.wantGroups), tokenClaims["groups"])

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
	const (
		oidcUpstreamName                  = "some-oidc-idp"
		oidcUpstreamResourceUID           = "oidc-resource-uid"
		oidcUpstreamType                  = "oidc"
		oidcUpstreamInitialRefreshToken   = "initial-upstream-refresh-token"
		oidcUpstreamRefreshedIDToken      = "fake-refreshed-id-token"
		oidcUpstreamRefreshedRefreshToken = "fake-refreshed-refresh-token"
		oidcUpstreamAccessToken           = "fake-upstream-access-token" //nolint:gosec

		ldapUpstreamName        = "some-ldap-idp"
		ldapUpstreamResourceUID = "ldap-resource-uid"
		ldapUpstreamType        = "ldap"
		ldapUpstreamDN          = "some-ldap-user-dn"

		activeDirectoryUpstreamName        = "some-ad-idp"
		activeDirectoryUpstreamResourceUID = "ad-resource-uid"
		activeDirectoryUpstreamType        = "activedirectory"
		activeDirectoryUpstreamDN          = "some-ad-user-dn"
	)

	ldapUpstreamURL, _ := url.Parse("some-url")

	// The below values are funcs so every test can have its own copy of the objects, to avoid data races
	// in these parallel tests.

	upstreamOIDCIdentityProviderBuilder := func() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName(oidcUpstreamName).
			WithResourceUID(oidcUpstreamResourceUID)
	}

	initialUpstreamOIDCRefreshTokenCustomSessionData := func() *psession.CustomSessionData {
		return &psession.CustomSessionData{
			ProviderName: oidcUpstreamName,
			ProviderUID:  oidcUpstreamResourceUID,
			ProviderType: oidcUpstreamType,
			OIDC: &psession.OIDCSessionData{
				UpstreamRefreshToken: oidcUpstreamInitialRefreshToken,
				UpstreamSubject:      goodUpstreamSubject,
				UpstreamIssuer:       goodIssuer,
			},
		}
	}

	initialUpstreamOIDCAccessTokenCustomSessionData := func() *psession.CustomSessionData {
		return &psession.CustomSessionData{
			ProviderName: oidcUpstreamName,
			ProviderUID:  oidcUpstreamResourceUID,
			ProviderType: oidcUpstreamType,
			OIDC: &psession.OIDCSessionData{
				UpstreamAccessToken: oidcUpstreamAccessToken,
				UpstreamSubject:     goodUpstreamSubject,
				UpstreamIssuer:      goodIssuer,
			},
		}
	}

	upstreamOIDCCustomSessionDataWithNewRefreshToken := func(newRefreshToken string) *psession.CustomSessionData {
		sessionData := initialUpstreamOIDCRefreshTokenCustomSessionData()
		sessionData.OIDC.UpstreamRefreshToken = newRefreshToken
		return sessionData
	}

	happyOIDCUpstreamRefreshCall := func() *expectedUpstreamRefresh {
		return &expectedUpstreamRefresh{
			performedByUpstreamName: oidcUpstreamName,
			args: &oidctestutil.PerformRefreshArgs{
				Ctx:          nil, // this will be filled in with the actual request context by the test below
				RefreshToken: oidcUpstreamInitialRefreshToken,
			},
		}
	}

	happyLDAPUpstreamRefreshCall := func() *expectedUpstreamRefresh {
		return &expectedUpstreamRefresh{
			performedByUpstreamName: ldapUpstreamName,
			args: &oidctestutil.PerformRefreshArgs{
				Ctx:              nil,
				DN:               ldapUpstreamDN,
				ExpectedSubject:  goodSubject,
				ExpectedUsername: goodUsername,
			},
		}
	}

	happyActiveDirectoryUpstreamRefreshCall := func() *expectedUpstreamRefresh {
		return &expectedUpstreamRefresh{
			performedByUpstreamName: activeDirectoryUpstreamName,
			args: &oidctestutil.PerformRefreshArgs{
				Ctx:              nil,
				DN:               activeDirectoryUpstreamDN,
				ExpectedSubject:  goodSubject,
				ExpectedUsername: goodUsername,
			},
		}
	}

	happyUpstreamValidateTokenCall := func(expectedTokens *oauth2.Token, requireIDToken bool) *expectedUpstreamValidateTokens {
		return &expectedUpstreamValidateTokens{
			performedByUpstreamName: oidcUpstreamName,
			args: &oidctestutil.ValidateTokenAndMergeWithUserInfoArgs{
				Ctx:                  nil, // this will be filled in with the actual request context by the test below
				Tok:                  expectedTokens,
				ExpectedIDTokenNonce: "", // always expect empty string
				RequireUserInfo:      false,
				RequireIDToken:       requireIDToken,
			},
		}
	}

	happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess := func(wantCustomSessionDataStored *psession.CustomSessionData) tokenEndpointResponseExpectedValues {
		want := tokenEndpointResponseExpectedValues{
			wantStatus:                  http.StatusOK,
			wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
			wantRequestedScopes:         []string{"openid", "offline_access"},
			wantGrantedScopes:           []string{"openid", "offline_access"},
			wantCustomSessionDataStored: wantCustomSessionDataStored,
			wantGroups:                  goodGroups,
		}
		return want
	}

	happyRefreshTokenResponseForOpenIDAndOfflineAccess := func(wantCustomSessionDataStored *psession.CustomSessionData, expectToValidateToken *oauth2.Token) tokenEndpointResponseExpectedValues {
		// Should always have some custom session data stored. The other expectations happens to be the
		// same as the same values as the authcode exchange case.
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		// Should always try to perform an upstream refresh.
		want.wantUpstreamRefreshCall = happyOIDCUpstreamRefreshCall()
		if expectToValidateToken != nil {
			want.wantUpstreamOIDCValidateTokenCall = happyUpstreamValidateTokenCall(expectToValidateToken, true)
		}
		return want
	}

	happyRefreshTokenResponseForLDAP := func(wantCustomSessionDataStored *psession.CustomSessionData) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		want.wantUpstreamRefreshCall = happyLDAPUpstreamRefreshCall()
		return want
	}

	happyRefreshTokenResponseForActiveDirectory := func(wantCustomSessionDataStored *psession.CustomSessionData) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		want.wantUpstreamRefreshCall = happyActiveDirectoryUpstreamRefreshCall()
		return want
	}

	refreshedUpstreamTokensWithRefreshTokenWithoutIDToken := func() *oauth2.Token {
		return &oauth2.Token{
			AccessToken:  "fake-refreshed-access-token",
			TokenType:    "Bearer",
			RefreshToken: oidcUpstreamRefreshedRefreshToken,
			Expiry:       time.Date(2050, 1, 1, 1, 1, 1, 1, time.UTC),
		}
	}

	refreshedUpstreamTokensWithIDAndRefreshTokens := func() *oauth2.Token {
		return refreshedUpstreamTokensWithRefreshTokenWithoutIDToken().
			WithExtra(map[string]interface{}{"id_token": oidcUpstreamRefreshedIDToken})
	}

	refreshedUpstreamTokensWithIDTokenWithoutRefreshToken := func() *oauth2.Token {
		tokens := refreshedUpstreamTokensWithIDAndRefreshTokens()
		tokens.RefreshToken = "" // remove the refresh token
		return tokens
	}

	happyActiveDirectoryCustomSessionData := &psession.CustomSessionData{
		ProviderUID:  activeDirectoryUpstreamResourceUID,
		ProviderName: activeDirectoryUpstreamName,
		ProviderType: activeDirectoryUpstreamType,
		ActiveDirectory: &psession.ActiveDirectorySessionData{
			UserDN: activeDirectoryUpstreamDN,
		},
	}
	happyLDAPCustomSessionData := &psession.CustomSessionData{
		ProviderUID:  ldapUpstreamResourceUID,
		ProviderName: ldapUpstreamName,
		ProviderType: ldapUpstreamType,
		LDAP: &psession.LDAPSessionData{
			UserDN: ldapUpstreamDN,
		},
	}
	tests := []struct {
		name                      string
		idps                      *oidctestutil.UpstreamIDPListerBuilder
		authcodeExchange          authcodeExchangeInputs
		refreshRequest            refreshRequestInputs
		modifyRefreshTokenStorage func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string)
	}{
		{
			name: "happy path refresh grant with openid scope granted (id token returned)",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				),
			},
		},
		{
			name: "refresh grant with unchanged username claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"some-claim":     "some-value",
							"sub":            goodUpstreamSubject,
							"username-claim": goodUsername,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				),
			},
		},
		{
			name: "refresh grant when the customsessiondata has a stored access token and no stored refresh token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").
					WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Claims: map[string]interface{}{
								"some-claim":     "some-value",
								"sub":            goodUpstreamSubject,
								"username-claim": goodUsername,
							},
						},
						AccessToken: &oidctypes.AccessToken{
							Token: oidcUpstreamAccessToken,
						},
					}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCAccessTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCAccessTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantSuccessBodyFields: []string{"refresh_token", "id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access"},
					wantGroups:            goodGroups,
					wantUpstreamOIDCValidateTokenCall: &expectedUpstreamValidateTokens{
						oidcUpstreamName,
						&oidctestutil.ValidateTokenAndMergeWithUserInfoArgs{
							Ctx:                  nil,                                                 // this will be filled in with the actual request context by the test below
							Tok:                  &oauth2.Token{AccessToken: oidcUpstreamAccessToken}, // only the old access token
							ExpectedIDTokenNonce: "",                                                  // always expect empty string
							RequireIDToken:       false,
							RequireUserInfo:      true,
						},
					},
					wantCustomSessionDataStored: initialUpstreamOIDCAccessTokenCustomSessionData(), // doesn't change when we refresh
				},
			},
		},
		{
			name: "happy path refresh grant without openid scope granted (no id token returned)",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access"},
					wantGrantedScopes:           []string{"offline_access"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				},
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"offline_access"},
					wantGrantedScopes:                 []string{"offline_access"},
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken(), false),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return a new ID token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access"},
					wantGroups:                        goodGroups,
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken(), false),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships (as strings) from the merged ID token and userinfo results, it updates groups",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access"},
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships (as interface{} types) from the merged ID token and userinfo results, it updates groups",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []interface{}{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access"},
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships as an empty list from the merged ID token and userinfo results, it updates groups to be empty",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{}, // refreshed groups claims is updated to be an empty list
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access"},
					wantGroups:                        []string{}, // the user no longer belongs to any groups
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return new group memberships from the merged ID token and userinfo results by omitting claim, it keeps groups from initial login",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
							// "my-groups-claim" is omitted from the refreshed claims
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access"},
					wantGroups:                        goodGroups, // the same groups as from the initial login
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships from LDAP, it updates groups",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:                 ldapUpstreamName,
				ResourceUID:          ldapUpstreamResourceUID,
				URL:                  ldapUpstreamURL,
				PerformRefreshGroups: []string{"new-group1", "new-group2", "new-group3"},
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access"},
					wantGrantedScopes:           []string{"openid", "offline_access"},
					wantGroups:                  []string{"new-group1", "new-group2", "new-group3"},
					wantUpstreamRefreshCall:     happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns empty list of group memberships from LDAP, it updates groups to an empty list",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:                 ldapUpstreamName,
				ResourceUID:          ldapUpstreamResourceUID,
				URL:                  ldapUpstreamURL,
				PerformRefreshGroups: []string{},
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access"},
					wantGrantedScopes:           []string{"openid", "offline_access"},
					wantGroups:                  []string{},
					wantUpstreamRefreshCall:     happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
				},
			},
		},
		{
			name: "error from refresh grant when the upstream refresh does not return new group memberships from the merged ID token and userinfo results by returning group claim with illegal nil value",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": nil,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody:             fositeUpstreamGroupClaimErrorBody,
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return a new refresh token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDTokenWithoutRefreshToken()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					initialUpstreamOIDCRefreshTokenCustomSessionData(), // still has the initial refresh token stored
					refreshedUpstreamTokensWithIDTokenWithoutRefreshToken(),
				),
			},
		},
		{
			name: "when the refresh request adds a new scope to the list of requested scopes then it is ignored",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid some-other-scope-not-from-auth-request").ReadCloser()
				},
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				),
			},
		},
		{
			name: "when the refresh request removes a scope which was originally granted from the list of requested scopes then it is granted anyway",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access pinniped:request-audience") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGrantedScopes:           []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGroups:                  goodGroups,
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid").ReadCloser() // do not ask for "pinniped:request-audience" again
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantSuccessBodyFields:             []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "pinniped:request-audience"},
					wantGroups:                        goodGroups,
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "when the refresh request does not include a scope param then it gets all the same scopes as the original authorization request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("").ReadCloser()
				},
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				),
			},
		},
		{
			name: "when a bad refresh token is sent in the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access"},
					wantGrantedScopes:           []string{"offline_access"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken("bad refresh token").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				},
			},
		},
		{
			name: "when the access token is sent as if it were a refresh token",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access"},
					wantGrantedScopes:           []string{"offline_access"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken(accessToken).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidAuthCodeErrorBody,
				},
			},
		},
		{
			name: "when the wrong client ID is included in the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access"},
					wantGrantedScopes:           []string{"offline_access"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithClientID("wrong-client-id").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeInvalidClientErrorBody,
				},
			},
		},
		{
			name: "when there is no custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: nil, // this should not happen in practice
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(nil),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is no provider name in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: "", // this should not happen in practice
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: "", // this should not happen in practice
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: oidcUpstreamType,
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is no provider UID in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  "", // this should not happen in practice
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  "", // this should not happen in practice
						ProviderType: oidcUpstreamType,
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is no provider type in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: "", // this should not happen in practice
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: "", // this should not happen in practice
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is an illegal provider type in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: "not-an-allowed-provider-type", // this should not happen in practice
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: "not-an-allowed-provider-type", // this should not happen in practice
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is no OIDC-specific data in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         nil, // this should not happen in practice
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: oidcUpstreamType,
						OIDC:         nil, // this should not happen in practice
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when there is no OIDC refresh token nor access token in custom session data found in the session storage during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC: &psession.OIDCSessionData{
						UpstreamRefreshToken: "", // this should not happen in practice. we should always have exactly one of these.
						UpstreamAccessToken:  "",
					},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: oidcUpstreamType,
						OIDC: &psession.OIDCSessionData{
							UpstreamRefreshToken: "", // this should not happen in practice
							UpstreamAccessToken:  "",
						},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusInternalServerError,
					wantErrorResponseBody: pinnipedUpstreamSessionDataNotFoundErrorBody,
				},
			},
		},
		{
			name: "when the provider in the session storage is not found due to its name during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: "this-name-will-not-be-found", // this could happen if the OIDCIdentityProvider was deleted since original login
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: "this-name-will-not-be-found", // this could happen if the OIDCIdentityProvider was deleted since original login
						ProviderUID:  oidcUpstreamResourceUID,
						ProviderType: oidcUpstreamType,
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data was not found."
						}
					`),
				},
			},
		},
		{
			name: "when the provider in the session storage is found but has the wrong resource UID during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  "this is the wrong uid", // this could happen if the OIDCIdentityProvider was deleted and recreated at the same name since original login
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						ProviderName: oidcUpstreamName,
						ProviderUID:  "this is the wrong uid", // this could happen if the OIDCIdentityProvider was deleted and recreated at the same name since original login
						ProviderType: oidcUpstreamType,
						OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data has changed its resource UID since authentication."
						}
					`),
				},
			},
		},
		{
			name: "when the upstream refresh fails during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithPerformRefreshError(errors.New("some upstream refresh error")).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall: happyOIDCUpstreamRefreshCall(),
					wantStatus:              http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "when the upstream refresh returns an invalid ID token during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
				// This is the current format of the errors returned by the production code version of ValidateTokenAndMergeWithUserInfo, see ValidateTokenAndMergeWithUserInfo in upstreamoidc.go
				WithValidateTokenAndMergeWithUserInfoError(httperr.Wrap(http.StatusBadRequest, "some validate error", errors.New("some validate cause"))).
				Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh returned an invalid ID token or UserInfo response."
						}
					`),
				},
			},
		},
		{
			name: "when the upstream refresh returns an ID token with a different subject than the original",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
				// This is the current format of the errors returned by the production code version of ValidateTokenAndMergeWithUserInfo, see ValidateTokenAndMergeWithUserInfo in upstreamoidc.go
				WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"sub": "something-different",
						},
					},
				}).
				Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "refresh grant with claims but not the subject claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"some-claim": "some-value",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "refresh grant with changed username claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"some-claim":     "some-value",
							"sub":            goodUpstreamSubject,
							"username-claim": "some-changed-username",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "refresh grant with changed issuer claim",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]interface{}{
							"some-claim": "some-value",
							"sub":        goodUpstreamSubject,
							"iss":        "some-changed-issuer",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall:           happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap refresh happy path",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:                 ldapUpstreamName,
				ResourceUID:          ldapUpstreamResourceUID,
				URL:                  ldapUpstreamURL,
				PerformRefreshGroups: goodGroups,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForLDAP(
					happyLDAPCustomSessionData,
				),
			},
		},
		{
			name: "upstream active directory refresh happy path",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:                 activeDirectoryUpstreamName,
				ResourceUID:          activeDirectoryUpstreamResourceUID,
				URL:                  ldapUpstreamURL,
				PerformRefreshGroups: goodGroups,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForActiveDirectory(
					happyActiveDirectoryCustomSessionData,
				),
			},
		},
		{
			name: "upstream ldap refresh when the LDAP session data is nil",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: &psession.CustomSessionData{
					ProviderUID:  ldapUpstreamResourceUID,
					ProviderName: ldapUpstreamName,
					ProviderType: ldapUpstreamType,
					LDAP:         nil,
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{
						ProviderUID:  ldapUpstreamResourceUID,
						ProviderName: ldapUpstreamName,
						ProviderType: ldapUpstreamType,
						LDAP:         nil,
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "upstream active directory refresh when the ad session data is nil",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        activeDirectoryUpstreamName,
				ResourceUID: activeDirectoryUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: &psession.CustomSessionData{
					ProviderUID:     activeDirectoryUpstreamResourceUID,
					ProviderName:    activeDirectoryUpstreamName,
					ProviderType:    activeDirectoryUpstreamType,
					ActiveDirectory: nil,
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{
						ProviderUID:     activeDirectoryUpstreamResourceUID,
						ProviderName:    activeDirectoryUpstreamName,
						ProviderType:    activeDirectoryUpstreamType,
						ActiveDirectory: nil,
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap refresh when the LDAP session data does not contain dn",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: &psession.CustomSessionData{
					ProviderUID:  ldapUpstreamResourceUID,
					ProviderName: ldapUpstreamName,
					ProviderType: ldapUpstreamType,
					LDAP: &psession.LDAPSessionData{
						UserDN: "",
					},
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{
						ProviderUID:  ldapUpstreamResourceUID,
						ProviderName: ldapUpstreamName,
						ProviderType: ldapUpstreamType,
						LDAP: &psession.LDAPSessionData{
							UserDN: "",
						},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "upstream active directory refresh when the active directory session data does not contain dn",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        activeDirectoryUpstreamName,
				ResourceUID: activeDirectoryUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: &psession.CustomSessionData{
					ProviderUID:  ldapUpstreamResourceUID,
					ProviderName: ldapUpstreamName,
					ProviderType: ldapUpstreamType,
					ActiveDirectory: &psession.ActiveDirectorySessionData{
						UserDN: "",
					},
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{
						ProviderUID:  ldapUpstreamResourceUID,
						ProviderName: ldapUpstreamName,
						ProviderType: ldapUpstreamType,
						ActiveDirectory: &psession.ActiveDirectorySessionData{
							UserDN: "",
						},
					},
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap refresh returns an error",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:              ldapUpstreamName,
				ResourceUID:       ldapUpstreamResourceUID,
				URL:               ldapUpstreamURL,
				PerformRefreshErr: errors.New("Some error performing upstream refresh"),
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantStatus:              http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "upstream active directory refresh returns an error",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:              activeDirectoryUpstreamName,
				ResourceUID:       activeDirectoryUpstreamResourceUID,
				URL:               ldapUpstreamURL,
				PerformRefreshErr: errors.New("Some error performing upstream refresh"),
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantUpstreamRefreshCall: happyActiveDirectoryUpstreamRefreshCall(),
					wantStatus:              http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh failed."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap idp not found",
			idps: oidctestutil.NewUpstreamIDPListerBuilder(),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data was not found."
						}
					`),
				},
			},
		},
		{
			name: "upstream active directory idp not found",
			idps: oidctestutil.NewUpstreamIDPListerBuilder(),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data was not found."
						}
					`),
				},
			},
		},
		{
			name: "fosite session is empty",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "username not found in extra field",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				//fositeSessionData: &openid.DefaultSession{},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Extra: map[string]interface{}{},
					},
				}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "username in extra is not a string",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				//fositeSessionData: &openid.DefaultSession{},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Extra: map[string]interface{}{"username": 123},
					},
				}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "username in extra is an empty string",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				//fositeSessionData: &openid.DefaultSession{},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Extra: map[string]interface{}{"username": ""},
					},
				}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "when the ldap provider in the session storage is found but has the wrong resource UID during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: "the-wrong-uid",
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data has changed its resource UID since authentication."
						}
					`),
				},
			},
		},
		{
			name: "when the active directory provider in the session storage is found but has the wrong resource UID during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        activeDirectoryUpstreamName,
				ResourceUID: "the-wrong-uid",
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data has changed its resource UID since authentication."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap idp not found",
			idps: oidctestutil.NewUpstreamIDPListerBuilder(),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data was not found."
						}
					`),
				},
			},
		},
		{
			name: "upstream active directory idp not found",
			idps: oidctestutil.NewUpstreamIDPListerBuilder(),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data was not found."
						}
					`),
				},
			},
		},
		{
			name: "fosite session is empty",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "username not found in extra field",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Extra: map[string]interface{}{},
					},
				}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "auth time is the zero value", // time.Times can never be nil, but it is possible that it would be the zero value which would mean something's wrong
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: ldapUpstreamResourceUID,
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *oidc.KubeStorage, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				fositeSessionClaims := session.Fosite.IDTokenClaims()
				fositeSessionClaims.AuthTime = time.Time{}
				session.Fosite.Claims = fositeSessionClaims
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, firstRequester)
				require.NoError(t, err)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusInternalServerError,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "There was an internal server error. Required upstream data not found in session."
						}
					`),
				},
			},
		},
		{
			name: "when the ldap provider in the session storage is found but has the wrong resource UID during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithLDAP(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        ldapUpstreamName,
				ResourceUID: "the-wrong-uid",
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data has changed its resource UID since authentication."
						}
					`),
				},
			},
		},
		{
			name: "when the active directory provider in the session storage is found but has the wrong resource UID during the refresh request",
			idps: oidctestutil.NewUpstreamIDPListerBuilder().WithActiveDirectory(&oidctestutil.TestUpstreamLDAPIdentityProvider{
				Name:        activeDirectoryUpstreamName,
				ResourceUID: "the-wrong-uid",
				URL:         ldapUpstreamURL,
			}),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus: http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Provider from upstream session data has changed its resource UID since authentication."
						}
					`),
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First exchange the authcode for tokens, including a refresh token.
			// its actually fine to use this function even when simulating ldap (which uses a different flow) because it's
			// just populating a secret in storage.
			subject, rsp, authCode, jwtSigningKey, secrets, oauthStore := exchangeAuthcodeForTokens(t, test.authcodeExchange, test.idps.Build())
			var parsedAuthcodeExchangeResponseBody map[string]interface{}
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedAuthcodeExchangeResponseBody))

			// Performing an authcode exchange should not have caused any upstream refresh, which should only
			// happen during a downstream refresh.
			test.idps.RequireExactlyZeroCallsToPerformRefresh(t)
			test.idps.RequireExactlyZeroCallsToValidateToken(t)

			// Wait one second before performing the refresh so we can see that the refreshed ID token has new issued
			// at and expires at dates which are newer than the old tokens.
			// If this gets too annoying in terms of making our test suite slower then we can remove it and adjust
			// the expectations about the ID token that are made at the end of this test accordingly.
			time.Sleep(1 * time.Second)

			// Send the refresh token back and preform a refresh.
			firstRefreshToken := parsedAuthcodeExchangeResponseBody["refresh_token"].(string)
			require.NotEmpty(t, firstRefreshToken)

			if test.modifyRefreshTokenStorage != nil {
				test.modifyRefreshTokenStorage(t, oauthStore, firstRefreshToken)
			}
			reqContext := context.WithValue(context.Background(), struct{ name string }{name: "test"}, "request-context")
			req := httptest.NewRequest("POST", "/path/shouldn't/matter",
				happyRefreshRequestBody(firstRefreshToken).ReadCloser()).WithContext(reqContext)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.refreshRequest.modifyTokenRequest != nil {
				test.refreshRequest.modifyTokenRequest(req, firstRefreshToken, parsedAuthcodeExchangeResponseBody["access_token"].(string))
			}

			refreshResponse := httptest.NewRecorder()
			subject.ServeHTTP(refreshResponse, req)
			t.Logf("second response: %#v", refreshResponse)
			t.Logf("second response body: %q", refreshResponse.Body.String())

			// Test that we did or did not make a call to the upstream OIDC provider interface to perform a token refresh.
			if test.refreshRequest.want.wantUpstreamRefreshCall != nil {
				test.refreshRequest.want.wantUpstreamRefreshCall.args.Ctx = reqContext
				test.idps.RequireExactlyOneCallToPerformRefresh(t,
					test.refreshRequest.want.wantUpstreamRefreshCall.performedByUpstreamName,
					test.refreshRequest.want.wantUpstreamRefreshCall.args,
				)
			} else {
				test.idps.RequireExactlyZeroCallsToPerformRefresh(t)
			}

			// Test that we did or did not make a call to the upstream OIDC provider interface to validate the
			// new ID token that was returned by the upstream refresh.
			if test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall != nil {
				test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.args.Ctx = reqContext
				test.idps.RequireExactlyOneCallToValidateToken(t,
					test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.performedByUpstreamName,
					test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.args,
				)
			} else {
				test.idps.RequireExactlyZeroCallsToValidateToken(t)
			}

			// Refreshed ID tokens do not include the nonce from the original auth request
			wantNonceValueInIDToken := false

			requireTokenEndpointBehavior(t,
				test.refreshRequest.want,
				test.authcodeExchange.want.wantGroups,   // the old groups from the initial login
				test.authcodeExchange.customSessionData, // the old custom session data from the initial login
				wantNonceValueInIDToken,
				refreshResponse,
				authCode,
				oauthStore,
				jwtSigningKey,
				secrets,
			)

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

					requireClaimsAreNotEqual(t, "jti", claimsOfFirstIDToken, claimsOfSecondIDToken)     // JWT ID
					requireClaimsAreNotEqual(t, "at_hash", claimsOfFirstIDToken, claimsOfSecondIDToken) // access token hash
					requireClaimsAreNotEqual(t, "exp", claimsOfFirstIDToken, claimsOfSecondIDToken)     // expires at
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

func exchangeAuthcodeForTokens(t *testing.T, test authcodeExchangeInputs, idps provider.DynamicUpstreamIDPProvider) (
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
		oauthHelper, authCode, jwtSigningKey = test.makeOathHelper(t, authRequest, oauthStore, test.customSessionData)
	} else {
		// Note that makeHappyOauthHelper() calls simulateAuthEndpointHavingAlreadyRun() to preload the session storage.
		oauthHelper, authCode, jwtSigningKey = makeHappyOauthHelper(t, authRequest, oauthStore, test.customSessionData)
	}

	if test.modifyStorage != nil {
		test.modifyStorage(t, oauthStore, authCode)
	}

	subject = NewHandler(idps, oauthHelper)

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

	wantNonceValueInIDToken := true // ID tokens returned by the authcode exchange must include the nonce from the auth request (unliked refreshed ID tokens)

	requireTokenEndpointBehavior(t,
		test.want,
		goodGroups,             // the old groups from the initial login
		test.customSessionData, // the old custom session data from the initial login
		wantNonceValueInIDToken,
		rsp,
		authCode,
		oauthStore,
		jwtSigningKey,
		secrets,
	)

	return subject, rsp, authCode, jwtSigningKey, secrets, oauthStore
}

func requireTokenEndpointBehavior(
	t *testing.T,
	test tokenEndpointResponseExpectedValues,
	oldGroups []string,
	oldCustomSessionData *psession.CustomSessionData,
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
		requireValidAccessTokenStorage(t, parsedResponseBody, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes, test.wantGroups, test.wantCustomSessionDataStored, secrets)
		requireInvalidPKCEStorage(t, authCode, oauthStore)
		// Performing a refresh does not update the OIDC storage, so after a refresh it should still have the old custom session data and old groups from the initial login.
		requireValidOIDCStorage(t, parsedResponseBody, authCode, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes, oldGroups, oldCustomSessionData)

		expectedNumberOfRefreshTokenSessionsStored := 0
		if wantRefreshToken {
			expectedNumberOfRefreshTokenSessionsStored = 1
		}
		expectedNumberOfIDSessionsStored := 0
		if wantIDToken {
			expectedNumberOfIDSessionsStored = 1
			requireValidIDToken(t, parsedResponseBody, jwtSigningKey, wantNonceValueInIDToken, test.wantGroups, parsedResponseBody["access_token"].(string))
		}
		if wantRefreshToken {
			requireValidRefreshTokenStorage(t, parsedResponseBody, oauthStore, test.wantRequestedScopes, test.wantGrantedScopes, test.wantGroups, test.wantCustomSessionDataStored, secrets)
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

type OauthHelperFactoryFunc func(
	t *testing.T,
	authRequest *http.Request,
	store fositestoragei.AllFositeStorage,
	initialCustomSessionData *psession.CustomSessionData,
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey)

func makeHappyOauthHelper(
	t *testing.T,
	authRequest *http.Request,
	store fositestoragei.AllFositeStorage,
	initialCustomSessionData *psession.CustomSessionData,
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwtSigningKey, jwkProvider := generateJWTSigningKeyAndJWKSProvider(t, goodIssuer)
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, jwkProvider, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper, initialCustomSessionData)
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
	store fositestoragei.AllFositeStorage,
	initialCustomSessionData *psession.CustomSessionData,
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwtSigningKey, jwkProvider := generateJWTSigningKeyAndJWKSProvider(t, goodIssuer)
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, &singleUseJWKProvider{DynamicJWKSProvider: jwkProvider}, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper, initialCustomSessionData)
	return oauthHelper, authResponder.GetCode(), jwtSigningKey
}

func makeOauthHelperWithNilPrivateJWTSigningKey(
	t *testing.T,
	authRequest *http.Request,
	store fositestoragei.AllFositeStorage,
	initialCustomSessionData *psession.CustomSessionData,
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwkProvider := jwks.NewDynamicJWKSProvider() // empty provider which contains no signing key for this issuer
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, jwkProvider, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper, initialCustomSessionData)
	return oauthHelper, authResponder.GetCode(), nil
}

// Simulate the auth endpoint running so Fosite code will fill the store with realistic values.
func simulateAuthEndpointHavingAlreadyRun(
	t *testing.T,
	authRequest *http.Request,
	oauthHelper fosite.OAuth2Provider,
	initialCustomSessionData *psession.CustomSessionData,
) fosite.AuthorizeResponder {
	// We only set the fields in the session that Fosite wants us to set.
	ctx := context.Background()
	session := &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
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
		},
		Custom: initialCustomSessionData,
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
	storage fositeoauth2.CoreStorage,
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
	storage fositeoauth2.CoreStorage,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
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

	// Refresh tokens should start with the custom prefix "pin_rt_" to make them identifiable as refresh tokens when seen by a user out of context.
	require.True(t, strings.HasPrefix(refreshTokenString, "pin_rt_"), "token %q did not have expected prefix 'pin_rt_'", refreshTokenString)

	// Fosite stores refresh tokens without any of the original request form parameters.
	requireValidStoredRequest(
		t,
		storedRequest,
		storedRequest.Sanitize([]string{}).GetRequestForm(),
		wantRequestedScopes,
		wantGrantedScopes,
		true,
		wantGroups,
		wantCustomSessionData,
	)

	requireGarbageCollectTimeInDelta(t, refreshTokenString, "refresh-token", secrets, time.Now().Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireValidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage fositeoauth2.CoreStorage,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
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

	// Access tokens should start with the custom prefix "pin_at_" to make them identifiable as access tokens when seen by a user out of context.
	require.True(t, strings.HasPrefix(accessTokenString, "pin_at_"), "token %q did not have expected prefix 'pin_at_'", accessTokenString)

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
		wantGroups,
		wantCustomSessionData,
	)

	requireGarbageCollectTimeInDelta(t, accessTokenString, "access-token", secrets, time.Now().Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireInvalidAccessTokenStorage(
	t *testing.T,
	body map[string]interface{},
	storage fositeoauth2.CoreStorage,
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
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
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
			wantGroups,
			wantCustomSessionData,
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
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
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
	session, ok := request.GetSession().(*psession.PinnipedSession)
	require.Truef(t, ok, "could not cast %T to %T", request.GetSession(), &psession.PinnipedSession{})

	// Assert that the session claims are what we think they should be, but only if we are doing OIDC.
	if contains(wantGrantedScopes, "openid") {
		claims := session.Fosite.Claims
		require.Empty(t, claims.JTI) // When claims.JTI is empty, Fosite will generate a UUID for this field.
		require.Equal(t, goodSubject, claims.Subject)

		// Our custom claims from the authorize endpoint should still be set.
		require.Equal(t, map[string]interface{}{
			"username": goodUsername,
			"groups":   toSliceOfInterface(wantGroups),
		}, claims.Extra)

		// We are in charge of setting these fields. For the purpose of testing, we ensure that the
		// sentinel test value is set correctly.
		require.Equal(t, goodRequestedAtTime, claims.RequestedAt)
		require.Equal(t, goodAuthTime, claims.AuthTime)

		// These fields will all be given good defaults by fosite at runtime and we only need to use them
		// if we want to override the default behaviors. We currently don't need to override these defaults,
		// so they do not end up being stored. Fosite sets its defaults at runtime in openid.DefaultStrategy's
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
		require.Empty(t, claims.AuthenticationMethodsReferences)
		require.Empty(t, claims.CodeHash)
	}

	// Assert that the session headers are what we think they should be.
	headers := session.Fosite.Headers
	require.Empty(t, headers)

	// Assert that the token expirations are what we think they should be.
	authCodeExpiresAt, ok := session.Fosite.ExpiresAt[fosite.AuthorizeCode]
	require.True(t, ok, "expected session to hold expiration time for auth code")
	testutil.RequireTimeInDelta(
		t,
		time.Now().UTC().Add(authCodeExpirationSeconds*time.Second),
		authCodeExpiresAt,
		timeComparisonFudgeSeconds*time.Second,
	)

	// OpenID Connect sessions do not store access token expiration information.
	accessTokenExpiresAt, ok := session.Fosite.ExpiresAt[fosite.AccessToken]
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
	require.Empty(t, session.Fosite.Username)
	require.Empty(t, session.Fosite.Subject)

	// The custom session data was stored as expected.
	require.Equal(t, wantCustomSessionData, session.Custom)
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
	wantNonceValueInIDToken bool,
	wantGroupsInIDToken []string,
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
		Groups          []string `json:"groups"`
		Username        string   `json:"username"`
	}

	idTokenFields := []string{"sub", "aud", "iss", "jti", "auth_time", "exp", "iat", "rat", "at_hash", "groups", "username"}
	if wantNonceValueInIDToken {
		idTokenFields = append(idTokenFields, "nonce")
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
	require.Equal(t, wantGroupsInIDToken, claims.Groups)
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

	require.NotEmpty(t, actualAccessToken)
	require.Equal(t, hashAccessToken(actualAccessToken), claims.AccessTokenHash)
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

func toSliceOfInterface(s []string) []interface{} {
	r := make([]interface{}, len(s))
	for i := range s {
		r[i] = s[i]
	}
	return r
}

func TestDiffSortedGroups(t *testing.T) {
	tests := []struct {
		name        string
		oldGroups   []string
		newGroups   []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "groups were added",
			oldGroups:   []string{"b", "c"},
			newGroups:   []string{"a", "b", "bb", "c", "d"},
			wantAdded:   []string{"a", "bb", "d"},
			wantRemoved: []string{},
		},
		{
			name:        "groups were removed",
			oldGroups:   []string{"a", "b", "bb", "c", "d"},
			newGroups:   []string{"b", "c"},
			wantAdded:   []string{},
			wantRemoved: []string{"a", "bb", "d"},
		},
		{
			name:        "groups were added and removed",
			oldGroups:   []string{"a", "c"},
			newGroups:   []string{"b", "c", "d"},
			wantAdded:   []string{"b", "d"},
			wantRemoved: []string{"a"},
		},
		{
			name:        "groups are exactly the same",
			oldGroups:   []string{"a", "b", "c"},
			newGroups:   []string{"a", "b", "c"},
			wantAdded:   []string{},
			wantRemoved: []string{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			added, removed := diffSortedGroups(test.oldGroups, test.newGroups)
			require.Equal(t, test.wantAdded, added)
			require.Equal(t, test.wantRemoved, removed)
		})
	}
}
