// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	fositepkce "github.com/ory/fosite/handler/pkce"
	fositejwt "github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/ptr"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/auditid"
	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/federationdomain/storage"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
	"go.pinniped.dev/internal/testutil/transformtestutil"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

const (
	goodIssuer           = "https://some-issuer.com"
	goodUpstreamSubject  = "some-subject"
	goodRedirectURI      = "http://127.0.0.1/callback"
	goodPKCECodeVerifier = "some-pkce-verifier-that-must-be-at-least-43-characters-to-meet-entropy-requirements"
	goodNonce            = "some-nonce-value-with-enough-bytes-to-exceed-min-allowed"
	goodSubject          = "https://issuer?sub=some-subject"
	goodUsername         = "some-username"

	pinnipedCLIClientID = "pinniped-cli"
	dynamicClientID     = "client.oauth.pinniped.dev-test-name"
	dynamicClientUID    = "fake-client-uid"

	hmacSecret = "this needs to be at least 32 characters to meet entropy requirements"

	authCodeExpirationSeconds    = 10 * 60 // Current, we set our auth code expiration to 10 minutes
	accessTokenExpirationSeconds = 2 * 60  // Currently, we set our access token expiration to 2 minutes
	idTokenExpirationSeconds     = 2 * 60  // Currently, we set our ID token expiration to 2 minutes

	timeComparisonFudge = 15 * time.Second
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
			"error_description": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse form params, make sure to send a properly formatted query params or form request body."
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

	fositeInvalidRefreshTokenErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The refresh token is malformed or not valid."
		}
	`)

	fositeExpiredRefreshTokenErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The refresh token expired."
		}
	`)

	fositeReusedAuthCodeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The authorization code has already been used."
		}
	`)

	fositeClientIDMismatchDuringAuthcodeExchangeErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the one from the authorize request."
		}
	`)

	fositeClientIDMismatchDuringRefreshErrorBody = here.Doc(`
		{
			"error":             "invalid_grant",
			"error_description": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."
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

	fositeClientAuthFailedErrorBody = here.Doc(`
		{
			"error":             "invalid_client",
			"error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
		}
	`)

	fositeClientAuthMustBeBasicAuthErrorBody = here.Doc(`
		{
			"error":             "invalid_client",
			"error_description": "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The OAuth 2.0 Client supports client authentication method 'client_secret_basic', but method 'client_secret_post' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept 'client_secret_post'."
		}
	`)

	happyAuthRequest = &http.Request{
		Form: url.Values{
			"response_type":         {"code"},
			"scope":                 {"openid profile email username groups"},
			"client_id":             {pinnipedCLIClientID},
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
				"client_id":            {pinnipedCLIClientID},
			},
		}
	}
)

type expectedOIDCUpstreamRefresh struct {
	performedByUpstreamName string
	args                    *oidctestutil.PerformOIDCRefreshArgs
}

type expectedLDAPUpstreamRefresh struct {
	performedByUpstreamName string
	args                    *oidctestutil.PerformLDAPRefreshArgs
}

type expectedGithubUpstreamRefresh struct {
	performedByUpstreamName string
	args                    *oidctestutil.GetUserArgs
}

type expectedOIDCUpstreamValidateTokens struct {
	performedByUpstreamName string
	args                    *oidctestutil.ValidateTokenAndMergeWithUserInfoArgs
}

type tokenEndpointResponseExpectedValues struct {
	wantStatus                             int
	wantSuccessBodyFields                  []string
	wantErrorResponseBody                  string
	wantClientID                           string
	wantRequestedScopes                    []string
	wantGrantedScopes                      []string
	wantUsername                           string
	wantGroups                             []string
	wantOIDCUpstreamRefreshCall            *expectedOIDCUpstreamRefresh
	wantLDAPUpstreamRefreshCall            *expectedLDAPUpstreamRefresh
	wantActiveDirectoryUpstreamRefreshCall *expectedLDAPUpstreamRefresh
	wantGithubUpstreamRefreshCall          *expectedGithubUpstreamRefresh
	wantUpstreamOIDCValidateTokenCall      *expectedOIDCUpstreamValidateTokens
	wantCustomSessionDataStored            *psession.CustomSessionData
	wantWarnings                           []RecordedWarning
	wantAdditionalClaims                   map[string]any
	// The expected lifetime of the ID tokens issued by authcode exchange and refresh, but not token exchange.
	// When zero, will assume that the test wants the default value for ID token lifetime.
	wantIDTokenLifetimeSeconds int
	wantAuditLogs              func(sessionID string, idToken string) []testutil.WantedAuditLog
}

func withWantCustomIDTokenLifetime(wantIDTokenLifetimeSeconds int, w tokenEndpointResponseExpectedValues) tokenEndpointResponseExpectedValues {
	w.wantIDTokenLifetimeSeconds = wantIDTokenLifetimeSeconds
	return w
}

type authcodeExchangeInputs struct {
	modifyAuthRequest             func(authRequest *http.Request)
	modifyTokenRequest            func(tokenRequest *http.Request, authCode string)
	makeJwksSigningKeyAndProvider MakeJwksSigningKeyAndProviderFunc
	customSessionData             *psession.CustomSessionData
	modifySession                 func(*psession.PinnipedSession)
	want                          tokenEndpointResponseExpectedValues
}

func addFullyCapableDynamicClientAndSecretToKubeResources(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
	oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
		"some-namespace",
		dynamicClientID,
		dynamicClientUID,
		goodRedirectURI,
		nil, // no custom ID token lifetime
		[]string{testutil.HashedPassword1AtGoMinCost, testutil.HashedPassword2AtGoMinCost},
		oidcclientvalidator.Validate,
	)
	require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
	require.NoError(t, kubeClient.Tracker().Add(secret))
}

func addFullyCapableDynamicClientWithCustomIDTokenLifetimeAndSecretToKubeResources(idTokenLifetime int32) func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
	return func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
		oidcClient, secret := testutil.FullyCapableOIDCClientAndStorageSecret(t,
			"some-namespace",
			dynamicClientID,
			dynamicClientUID,
			goodRedirectURI,
			ptr.To(idTokenLifetime), // with custom ID token lifetime
			[]string{testutil.HashedPassword1AtGoMinCost, testutil.HashedPassword2AtGoMinCost},
			oidcclientvalidator.Validate,
		)
		require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
		require.NoError(t, kubeClient.Tracker().Add(secret))
	}
}

func modifyAuthcodeTokenRequestWithDynamicClientAuth(r *http.Request, authCode string) {
	r.Body = happyAuthcodeRequestBody(authCode).WithClientID("").ReadCloser() // No client_id in body.
	r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)              // Use basic auth header instead.
}

func addDynamicClientIDToFormPostBody(r *http.Request) {
	r.Form.Set("client_id", dynamicClientID)
}

func idTokenToHash(tok string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(tok)))
}

func TestTokenEndpointAuthcodeExchange(t *testing.T) {
	tests := []struct {
		name             string
		authcodeExchange authcodeExchangeInputs
		kubeResources    func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
	}{
		// happy path
		{
			name: "request is valid and tokens are issued",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid profile email username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "profile", "email", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "656 Bytes", // the token contents may be random, but the size is predictable
							}),
						}
					},
				},
			},
		},
		{
			name: "request is valid and tokens are issued with additional claims",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid profile email username groups") },
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
					}
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "profile", "email", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				},
			},
		},
		{
			name:          "request is valid and tokens are issued for dynamic client",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("HTTP Request Basic Auth", map[string]any{"clientID": dynamicClientID}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "718 Bytes", // the token contents may be random, but the size is predictable
							}),
						}
					},
				},
			},
		},
		{
			name:          "request is valid and tokens are issued for dynamic client which has a custom ID token lifetime",
			kubeResources: addFullyCapableDynamicClientWithCustomIDTokenLifetimeAndSecretToKubeResources(4242),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                 http.StatusOK,
					wantClientID:               dynamicClientID,
					wantSuccessBodyFields:      []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:        []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:          []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantUsername:               goodUsername,
					wantGroups:                 goodGroups,
					wantIDTokenLifetimeSeconds: 4242,
				},
			},
		},
		{
			name:          "request is valid and tokens are issued for dynamic client with additional claims",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
					}
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				},
			},
		},
		{
			name: "openid scope was not requested from authorize endpoint",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "profile email") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in"}, // no id or refresh tokens
					wantRequestedScopes:   []string{"profile", "email"},
					wantGrantedScopes:     []string{"username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
						}
					},
				},
			},
		},
		{
			name:          "openid scope was not requested from authorize endpoint for dynamic client",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "pinniped:request-audience username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in"}, // no id or refresh tokens
					wantRequestedScopes:   []string{"pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("HTTP Request Basic Auth", map[string]any{"clientID": dynamicClientID}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							// Note that there was no ID token issued, so there is no "ID Token Issued" audit log.
						}
					},
				},
			},
		},
		{
			name: "offline_access and openid scopes were requested and granted from authorize endpoint (no username or groups requested)",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in", "refresh_token"}, // all possible tokens
					wantRequestedScopes:   []string{"openid", "offline_access"},
					wantGrantedScopes:     []string{"openid", "offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
		},
		{
			name:          "openid, offline_access, and username scopes (no groups) were requested and granted from authorize endpoint for dynamic client",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in", "refresh_token"}, // all possible tokens
					wantRequestedScopes:   []string{"openid", "offline_access", "username"},
					wantGrantedScopes:     []string{"openid", "offline_access", "username"},
					wantUsername:          goodUsername,
					wantGroups:            nil,
				},
			},
		},
		{
			name:          "openid, offline_access, and groups scopes (no username) were requested and granted from authorize endpoint for dynamic client",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in", "refresh_token"}, // all possible tokens
					wantRequestedScopes:   []string{"openid", "offline_access", "groups"},
					wantGrantedScopes:     []string{"openid", "offline_access", "groups"},
					wantUsername:          "",
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
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in", "refresh_token"}, // no id token
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
		},
		{
			name:          "offline_access (without openid, username, groups scopes) was requested and granted from authorize endpoint for dynamic client",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "offline_access")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "scope", "expires_in", "refresh_token"}, // no id token
					wantRequestedScopes:   []string{"offline_access"},
					wantGrantedScopes:     []string{"offline_access"},
					wantUsername:          "",
					wantGroups:            nil,
				},
			},
		},
		{
			name: "username and groups scopes are requested",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid profile email username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "profile", "email", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
		},
		{
			name:          "dynamic client uses a secondary client secret (one of the other client secrets after the first one in the list)",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience groups")
				},
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithClientID("").ReadCloser()
					r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword2) // use the second client secret that was configured on the client
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "scope", "expires_in"}, // no refresh token
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "groups"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "groups"},
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
			name:          "dynamic client uses wrong client secret",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience groups")
				},
				modifyTokenRequest: func(r *http.Request, authCode string) {
					r.Body = happyAuthcodeRequestBody(authCode).WithClientID("").ReadCloser()
					r.SetBasicAuth(dynamicClientID, "wrong client secret")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeClientAuthFailedErrorBody,
				},
			},
		},
		{
			name:          "dynamic client uses wrong auth method (must use basic auth)",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid pinniped:request-audience groups")
				},
				modifyTokenRequest: func(r *http.Request, authCode string) {
					// Add client auth to the form, when it should be in basic auth headers.
					r.Body = happyAuthcodeRequestBody(authCode).WithClientID(dynamicClientID).WithClientSecret(testutil.PlaintextPassword1).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeClientAuthMustBeBasicAuthErrorBody,
				},
			},
		},
		{
			name:          "tries to change client ID between authorization request and token request",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					// Test uses pinniped-cli client_id by default here.
					r.Form.Set("scope", "openid pinniped:request-audience")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeClientIDMismatchDuringAuthcodeExchangeErrorBody,
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
					r.Body = io.NopCloser(strings.NewReader("this newline character is not allowed in a form serialization: \n"))
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
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":    "pinniped-cli",
									"code":         "redacted",
									"grant_type":   "authorization_code",
									"redirect_uri": "http://127.0.0.1/callback",
								},
							}),
						}
					},
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
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
						}
					},
				},
			},
		},
		{
			name: "private signing key for JWTs has not yet been provided by the controller who is responsible for dynamically providing it",
			authcodeExchange: authcodeExchangeInputs{
				makeJwksSigningKeyAndProvider: func(t *testing.T, issuer string) (*ecdsa.PrivateKey, jwks.DynamicJWKSProvider) {
					return nil, jwks.NewDynamicJWKSProvider()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusServiceUnavailable,
					wantErrorResponseBody: fositeTemporarilyUnavailableErrorBody,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			exchangeAuthcodeForTokens(t,
				test.authcodeExchange, testidplister.NewUpstreamIDPListerBuilder().BuildFederationDomainIdentityProvidersListerFinder(), test.kubeResources)
		})
	}
}

func TestTokenEndpointWhenAuthcodeIsUsedTwice(t *testing.T) {
	tests := []struct {
		name             string
		authcodeExchange authcodeExchangeInputs
		kubeResources    func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
	}{
		{
			name: "authcode exchange succeeds once and then fails when the same authcode is used again",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access profile email username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access", "profile", "email", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "offline_access", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First call - should be successful.
			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			subject, rsp, authCode, _, secrets, oauthStore, _, _ := exchangeAuthcodeForTokens(t,
				test.authcodeExchange, testidplister.NewUpstreamIDPListerBuilder().BuildFederationDomainIdentityProvidersListerFinder(), test.kubeResources)
			var parsedResponseBody map[string]any
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedResponseBody))

			// Second call - should be unsuccessful since auth code was already used.
			//
			// Fosite will also revoke the access token as is recommended by the OIDC spec. Currently, we don't
			// delete the OIDC storage...but we probably should.
			req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyAuthcodeRequestBody(authCode).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reusedAuthcodeResponse := httptest.NewRecorder()
			approxRequestTime := time.Now()
			subject.ServeHTTP(reusedAuthcodeResponse, req)
			t.Logf("second response: %#v", reusedAuthcodeResponse)
			t.Logf("second response body: %q", reusedAuthcodeResponse.Body.String())
			require.Equal(t, http.StatusBadRequest, reusedAuthcodeResponse.Code)
			testutil.RequireEqualContentType(t, reusedAuthcodeResponse.Header().Get("Content-Type"), "application/json")
			require.JSONEq(t, fositeReusedAuthCodeErrorBody, reusedAuthcodeResponse.Body.String())

			// This was previously invalidated by the first request, so it remains invalidated
			requireInvalidAuthCodeStorage(t, authCode, oauthStore, secrets, approxRequestTime)
			// Has now invalidated the access token that was previously handed out by the first request
			requireInvalidAccessTokenStorage(t, parsedResponseBody, oauthStore)
			// This was previously invalidated by the first request, so it remains invalidated
			requireInvalidPKCEStorage(t, authCode, oauthStore)
			// OpenID Connect session storage is deleted during a successful authcode exchange.
			requireDeletedOIDCStorage(t, authCode, oauthStore)

			// Check that the access token and refresh token storage were both deleted, and the number of other storage objects did not change.
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: accesstoken.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: refreshtoken.TypeLabelValue}, 0)
			testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: pkce.TypeLabelValue}, 0)
			// Assert the number of all secrets, excluding any OIDCClient's storage secret, since those are not related to session storage.
			testutil.RequireNumberOfSecretsExcludingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: oidcclientsecretstorage.TypeLabelValue}, 1)
		})
	}
}

func TestTokenEndpointTokenExchange(t *testing.T) { // tests for grant_type "urn:ietf:params:oauth:grant-type:token-exchange"
	successfulAuthCodeExchange := tokenEndpointResponseExpectedValues{
		wantStatus:            http.StatusOK,
		wantClientID:          pinnipedCLIClientID,
		wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
		wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
		wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
		wantUsername:          goodUsername,
		wantGroups:            goodGroups,
	}

	successfulAuthCodeExchangeUsingDynamicClient := func() tokenEndpointResponseExpectedValues {
		return tokenEndpointResponseExpectedValues{
			wantStatus:            http.StatusOK,
			wantClientID:          dynamicClientID,
			wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
			wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
			wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
			wantUsername:          goodUsername,
			wantGroups:            goodGroups,
		}
	}

	doValidAuthCodeExchange := authcodeExchangeInputs{
		modifyAuthRequest: func(authRequest *http.Request) {
			authRequest.Form.Set("scope", "openid pinniped:request-audience username groups")
		},
		want: successfulAuthCodeExchange,
	}

	doValidAuthCodeExchangeUsingDynamicClient := func() authcodeExchangeInputs {
		return authcodeExchangeInputs{
			modifyAuthRequest: func(authRequest *http.Request) {
				addDynamicClientIDToFormPostBody(authRequest)
				authRequest.Form.Set("scope", "openid pinniped:request-audience username groups")
			},
			modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
			want:               successfulAuthCodeExchangeUsingDynamicClient(),
		}
	}

	tests := []struct {
		name string

		authcodeExchange     authcodeExchangeInputs
		modifyRequestParams  func(t *testing.T, params url.Values)
		modifyRequestHeaders func(r *http.Request)
		modifyStorage        func(t *testing.T, storage *storage.KubeStorage, secrets v1.SecretInterface, pendingRequest *http.Request)
		requestedAudience    string
		kubeResources        func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)

		wantStatus            int
		wantErrorType         string
		wantErrorDescContains string
		wantAuditLogs         func(sessionID string, idToken string) []testutil.WantedAuditLog
	}{
		{
			name:              "happy path",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name: "happy path with additional claims",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
						"upstreamLargeStrings": []string{
							"45721694-1b78-49cf-95fd-4e326fecb288",
							"5578bc6d-a1a1-419b-9522-a35e4dbb4dc8",
							"0fd65787-0848-4f64-8959-fda114e63a6c",
							"dbfdf47a-ab4c-4dba-ad59-7284c8b935f2",
							"f8e397ba-f18f-4a9e-92df-e1d92356d394",
							"4f8153d5-bc9d-4859-8da4-2a4cbdcab9fc",
							"28de15cb-86bd-48e3-b9f2-27a75c35c7eb",
							"331253a2-fdf7-4f8b-9768-50d53a12668b",
							"9ceef90d-6d1c-40de-92ee-e633362541c3",
							"892da1d3-6fdc-4572-8a31-bfe282994329",
						},
					}
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
						"upstreamLargeStrings": []any{
							"45721694-1b78-49cf-95fd-4e326fecb288",
							"5578bc6d-a1a1-419b-9522-a35e4dbb4dc8",
							"0fd65787-0848-4f64-8959-fda114e63a6c",
							"dbfdf47a-ab4c-4dba-ad59-7284c8b935f2",
							"f8e397ba-f18f-4a9e-92df-e1d92356d394",
							"4f8153d5-bc9d-4859-8da4-2a4cbdcab9fc",
							"28de15cb-86bd-48e3-b9f2-27a75c35c7eb",
							"331253a2-fdf7-4f8b-9768-50d53a12668b",
							"9ceef90d-6d1c-40de-92ee-e633362541c3",
							"892da1d3-6fdc-4572-8a31-bfe282994329",
						},
					},
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "1.41 KiB", // the token contents may be random, but the size is predictable
							}),
						}
					},
				},
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
			wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{
							"audience":             "some-workload-cluster",
							"client_id":            "pinniped-cli",
							"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
							"requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
							"subject_token":        "redacted",
							"subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
						},
					}),
					testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
					testutil.WantAuditLog("ID Token Issued", map[string]any{
						"sessionID": sessionID,
						"tokenID":   idTokenToHash(idToken),
						"tokenSize": "1.28 KiB", // the token contents may be random, but the size is predictable
					}),
				}
			},
		},
		{
			name: "happy path without requesting username and groups scopes",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid pinniped:request-audience")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "expires_in", "scope", "id_token"},
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name:             "happy path with dynamic client",
			kubeResources:    addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: doValidAuthCodeExchangeUsingDynamicClient(),
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name:          "happy path with dynamic client which has a custom ID token lifetime configuration (which does not apply to ID tokens from token exchanges)",
			kubeResources: addFullyCapableDynamicClientWithCustomIDTokenLifetimeAndSecretToKubeResources(4242),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest:  doValidAuthCodeExchangeUsingDynamicClient().modifyAuthRequest,
				modifyTokenRequest: doValidAuthCodeExchangeUsingDynamicClient().modifyTokenRequest,
				want: withWantCustomIDTokenLifetime(
					4242, // want custom lifetime for authcode exchange (but not for token exchange)
					doValidAuthCodeExchangeUsingDynamicClient().want,
				),
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name:          "happy path with dynamic client and additional claims",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
					}
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name:          "happy path with dynamic client without requesting groups, so gets no groups in ID tokens",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "openid pinniped:request-audience username") // don't request groups scope
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "username"}, // don't want groups scope
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "username"}, // don't want groups scope
					wantUsername:          goodUsername,
					wantGroups:            nil,
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience: "some-workload-cluster",
			wantStatus:        http.StatusOK,
		},
		{
			name: "dynamic client lacks the required urn:ietf:params:oauth:grant-type:token-exchange grant type",
			kubeResources: func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset) {
				namespace, clientID, clientUID, redirectURI := "some-namespace", dynamicClientID, dynamicClientUID, goodRedirectURI
				oidcClient := &supervisorconfigv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: clientID, Generation: 1, UID: types.UID(clientUID)},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"},        // does not have the grant type
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username", "groups"}, // would be invalid if it also asked for pinniped:request-audience since it lacks the grant type
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{supervisorconfigv1alpha1.RedirectURI(redirectURI)},
					},
				}
				secret := testutil.OIDCClientSecretStorageSecretForUID(t, namespace, clientUID, []string{testutil.HashedPassword1AtGoMinCost, testutil.HashedPassword2AtGoMinCost})
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
				require.NoError(t, kubeClient.Tracker().Add(secret))
			},
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "openid username groups") // don't request pinniped:request-audience scope
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "username", "groups"}, // don't want pinniped:request-audience scope
					wantGrantedScopes:     []string{"openid", "username", "groups"}, // don't want pinniped:request-audience scope
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "unauthorized_client",
			wantErrorDescContains: `The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use token exchange grant 'urn:ietf:params:oauth:grant-type:token-exchange'.`,
			wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{
							"audience":             "some-workload-cluster",
							"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
							"requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
							"subject_token":        "redacted",
							"subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
						},
					}),
					testutil.WantAuditLog("HTTP Request Basic Auth", map[string]any{"clientID": dynamicClientID}),
				}
			},
		},
		{
			name:          "dynamic client did not ask for the pinniped:request-audience scope in the original authorization request, so the access token submitted during token exchange lacks the scope",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "openid username groups") // don't request pinniped:request-audience scope
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "username", "groups"}, // don't want pinniped:request-audience scope
					wantGrantedScopes:     []string{"openid", "username", "groups"}, // don't want pinniped:request-audience scope
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusForbidden,
			wantErrorType:         "access_denied",
			wantErrorDescContains: `The resource owner or authorization server denied the request. Missing the 'pinniped:request-audience' scope.`,
		},
		{
			name:          "dynamic client did not ask for the openid scope in the original authorization request, so the access token submitted during token exchange lacks the scope",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "pinniped:request-audience username groups") // don't request openid scope
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "expires_in", "scope"}, // no id token
					wantRequestedScopes:   []string{"pinniped:request-audience", "username", "groups"},   // don't want openid scope
					wantGrantedScopes:     []string{"pinniped:request-audience", "username", "groups"},   // don't want openid scope
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusForbidden,
			wantErrorType:         "access_denied",
			wantErrorDescContains: `The resource owner or authorization server denied the request. Missing the 'openid' scope.`,
		},
		{
			name:          "dynamic client did not ask for the username scope in the original authorization request, so the session during token exchange has no username associated with it",
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					addDynamicClientIDToFormPostBody(authRequest)
					authRequest.Form.Set("scope", "openid pinniped:request-audience groups") // don't request username scope
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          dynamicClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "pinniped:request-audience", "groups"}, // no username scope
					wantGrantedScopes:     []string{"openid", "pinniped:request-audience", "groups"}, // no username scope
					wantUsername:          "",
					wantGroups:            goodGroups,
				},
			},
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusForbidden,
			wantErrorType:         "access_denied",
			wantErrorDescContains: `The resource owner or authorization server denied the request. No username found in session. Ensure that the 'username' scope was requested and granted at the authorization endpoint.`,
		},
		{
			name:                  "missing audience",
			authcodeExchange:      doValidAuthCodeExchange,
			requestedAudience:     "",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: "Missing 'audience' parameter.",
			wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{
							"audience":             "", // make it obvious
							"client_id":            "pinniped-cli",
							"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
							"requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
							"subject_token":        "redacted",
							"subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
						},
					}),
				}
			},
		},
		{
			name:                  "bad requested audience when it looks like the name of an OIDCClient CR",
			authcodeExchange:      doValidAuthCodeExchange,
			requestedAudience:     "client.oauth.pinniped.dev-some-client-abc123",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: "requested audience cannot contain '.pinniped.dev'",
		},
		{
			name:                  "bad requested audience when it contains the substring .pinniped.dev because it is reserved for potential future usage",
			authcodeExchange:      doValidAuthCodeExchange,
			requestedAudience:     "something.pinniped.dev/some_aud",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: "requested audience cannot contain '.pinniped.dev'",
		},
		{
			name:                  "bad requested audience when it is the same name as the static public client pinniped-cli",
			authcodeExchange:      doValidAuthCodeExchange,
			requestedAudience:     "pinniped-cli",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: "requested audience cannot equal 'pinniped-cli'",
		},
		{
			name:              "missing subject_token",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("subject_token")
			},
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: "Missing 'subject_token' parameter.",
		},
		{
			name:              "wrong subject_token_type",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("subject_token_type", "invalid")
			},
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: `Unsupported 'subject_token_type' parameter value, must be 'urn:ietf:params:oauth:token-type:access_token'.`,
		},
		{
			name:              "wrong requested_token_type",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("requested_token_type", "invalid")
			},
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: `Unsupported 'requested_token_type' parameter value, must be 'urn:ietf:params:oauth:token-type:jwt'.`,
		},
		{
			name:              "unsupported RFC8693 parameter",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("resource", "some-resource-parameter-value")
			},
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_request",
			wantErrorDescContains: `Unsupported parameter 'resource'.`,
		},
		{
			name:              "bogus access token",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("subject_token", "some-bogus-value")
			},
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "request_unauthorized",
			wantErrorDescContains: `The request could not be authorized. Invalid 'subject_token' parameter value.`,
		},
		{
			name:              "bad client ID",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Set("client_id", "some-bogus-value")
			},
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "invalid_client",
			wantErrorDescContains: `Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).`,
		},
		{
			name:             "dynamic client uses wrong client secret",
			kubeResources:    addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: doValidAuthCodeExchangeUsingDynamicClient(),
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, "bad client secret")
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "invalid_client",
			wantErrorDescContains: `Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).`,
		},
		{
			name:             "dynamic client uses wrong auth method (must use basic auth)",
			kubeResources:    addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: doValidAuthCodeExchangeUsingDynamicClient(),
			modifyRequestParams: func(t *testing.T, params url.Values) {
				// Dynamic clients do not support this method of auth.
				params.Set("client_id", dynamicClientID)
				params.Set("client_secret", testutil.PlaintextPassword1)
			},
			modifyRequestHeaders: func(r *http.Request) {
				// would usually set the basic auth header here, but we don't for this test case
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "invalid_client",
			wantErrorDescContains: `Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The OAuth 2.0 Client supports client authentication method 'client_secret_basic', but method 'client_secret_post' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept 'client_secret_post'.`,
		},
		{
			name:             "different client used between authorize/authcode calls and the call to token exchange",
			kubeResources:    addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: doValidAuthCodeExchange, // use pinniped-cli for authorize and authcode exchange
			modifyRequestParams: func(t *testing.T, params url.Values) {
				params.Del("client_id") // client auth for dynamic clients must be in basic auth header
			},
			modifyRequestHeaders: func(r *http.Request) {
				r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1) // use dynamic client for token exchange
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusBadRequest,
			wantErrorType:         "invalid_grant",
			wantErrorDescContains: `The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the one from the authorize request.`,
		},
		{
			name:              "valid access token, but it was already deleted from storage",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyStorage: func(t *testing.T, storage *storage.KubeStorage, secrets v1.SecretInterface, pendingRequest *http.Request) {
				parts := strings.Split(pendingRequest.Form.Get("subject_token"), ".")
				require.Len(t, parts, 2)
				require.NoError(t, storage.DeleteAccessTokenSession(context.Background(), parts[1]))
			},
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "request_unauthorized",
			wantErrorDescContains: `Invalid 'subject_token' parameter value.`,
		},
		{
			name:              "valid access token, but it has already expired",
			authcodeExchange:  doValidAuthCodeExchange,
			requestedAudience: "some-workload-cluster",
			modifyStorage: func(t *testing.T, storage *storage.KubeStorage, secrets v1.SecretInterface, pendingRequest *http.Request) {
				// The fosite storage APIs don't offer a way to update an access token, so we will instead find the underlying
				// storage Secret and update it in a more manual way. First get the access token's signature.
				parts := strings.Split(pendingRequest.Form.Get("subject_token"), ".")
				require.Len(t, parts, 2)
				// Find the storage Secret for the access token by using its signature to compute the Secret name.
				accessTokenSignature := parts[1]
				accessTokenSecretName := getSecretNameFromSignature(t, accessTokenSignature, "access-token") // "access-token" is the storage type used in the Secret's name
				accessTokenSecret, err := secrets.Get(context.Background(), accessTokenSecretName, metav1.GetOptions{})
				require.NoError(t, err)
				// Parse the session from the storage Secret.
				savedSessionJSON := accessTokenSecret.Data["pinniped-storage-data"]
				// Declare the appropriate empty struct, similar to how our kubestorage implementation
				// of GetAccessTokenSession() does when parsing a session from a storage Secret.
				accessTokenSession := &accesstoken.Session{
					Request: &fosite.Request{
						Client:  &clientregistry.Client{},
						Session: &psession.PinnipedSession{},
					},
				}
				// Parse the session JSON and fill the empty struct with its data.
				err = json.Unmarshal(savedSessionJSON, accessTokenSession)
				require.NoError(t, err)
				// Change the access token's expiration time to be one hour ago, so it will be considered already expired.
				oneHourAgoInUTC := time.Now().UTC().Add(-1 * time.Hour)
				accessTokenSession.Request.Session.(*psession.PinnipedSession).Fosite.SetExpiresAt(fosite.AccessToken, oneHourAgoInUTC)
				// Write the updated session back to the access token's storage Secret.
				updatedSessionJSON, err := json.Marshal(accessTokenSession)
				require.NoError(t, err)
				accessTokenSecret.Data["pinniped-storage-data"] = updatedSessionJSON
				_, err = secrets.Update(context.Background(), accessTokenSecret, metav1.UpdateOptions{})
				require.NoError(t, err)
				// Just to be sure that this test setup is valid, confirm that the code above correctly updated the
				// access token's expiration time by reading it again, this time performing the read using the
				// kubestorage API instead of the manual/direct approach used above.
				session, err := storage.GetAccessTokenSession(context.Background(), accessTokenSignature, nil)
				require.NoError(t, err)
				expiresAt := session.GetSession().GetExpiresAt(fosite.AccessToken)
				require.Equal(t, oneHourAgoInUTC, expiresAt)
			},
			wantStatus:            http.StatusUnauthorized,
			wantErrorType:         "invalid_token",
			wantErrorDescContains: `Token expired. Access token expired at `,
		},
		{
			name: "access token missing pinniped:request-audience scope",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid username groups")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusForbidden,
			wantErrorType:         "access_denied",
			wantErrorDescContains: `Missing the 'pinniped:request-audience' scope.`,
		},
		{
			name: "access token missing openid scope",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "pinniped:request-audience username groups")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:     []string{"pinniped:request-audience", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
				},
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusForbidden,
			wantErrorType:         "access_denied",
			wantErrorDescContains: `Missing the 'openid' scope.`,
		},
		{
			name: "token minting failure",
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(authRequest *http.Request) {
					authRequest.Form.Set("scope", "openid pinniped:request-audience username groups")
				},
				// Fail to fetch a JWK signing key after the authcode exchange has happened.
				makeJwksSigningKeyAndProvider: func(t *testing.T, issuer string) (*ecdsa.PrivateKey, jwks.DynamicJWKSProvider) {
					jwtSigningKey, jwkProvider := generateJWTSigningKeyAndJWKSProvider(t, goodIssuer)
					return jwtSigningKey, &singleUseJWKProvider{DynamicJWKSProvider: jwkProvider}
				},
				want: successfulAuthCodeExchange,
			},
			requestedAudience:     "some-workload-cluster",
			wantStatus:            http.StatusServiceUnavailable,
			wantErrorType:         "temporarily_unavailable",
			wantErrorDescContains: `The authorization server is currently unable to handle the request`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Authcode exchange doesn't use the upstream provider cache, so just pass an empty cache.
			subject, rsp, _, _, secrets, oauthStore, actualAuditLog, actualSessionID := exchangeAuthcodeForTokens(t,
				test.authcodeExchange, testidplister.NewUpstreamIDPListerBuilder().BuildFederationDomainIdentityProvidersListerFinder(), test.kubeResources)
			var parsedAuthcodeExchangeResponseBody map[string]any
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedAuthcodeExchangeResponseBody))

			request := happyTokenExchangeRequest(test.requestedAudience, parsedAuthcodeExchangeResponseBody["access_token"].(string))
			if test.modifyStorage != nil {
				test.modifyStorage(t, oauthStore, secrets, request)
			}
			if test.modifyRequestParams != nil {
				test.modifyRequestParams(t, request.Form)
			}

			req := httptest.NewRequest("POST", "/token/exchange/path/shouldn't/matter", body(request.Form).ReadCloser())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req, _ = auditid.NewRequestWithAuditID(req, func() string { return "fake-token-exchange-audit-id" })
			rsp = httptest.NewRecorder()

			if test.modifyRequestHeaders != nil {
				test.modifyRequestHeaders(req)
			}

			// Measure the secrets in storage after the auth code flow.
			existingSecrets, err := secrets.List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)

			// Wait one second before performing the token exchange so we can see that the new ID token has new issued
			// at and expires at dates which are newer than the old tokens.
			time.Sleep(1 * time.Second)

			// Perform the token exchange.
			approxRequestTime := time.Now()
			actualAuditLog.Reset() // Clear audit logs from the authcode exchange
			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), "application/json")

			var parsedResponseBody map[string]any
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedResponseBody))

			if rsp.Code != http.StatusOK {
				// All error responses should have two JSON keys.
				require.Len(t, parsedResponseBody, 2)

				errorType := parsedResponseBody["error"]
				require.NotEmpty(t, errorType)
				require.Equal(t, test.wantErrorType, errorType)

				errorDesc := parsedResponseBody["error_description"]
				require.NotEmpty(t, errorDesc)
				require.Contains(t, errorDesc, test.wantErrorDescContains)

				// Even in the error case, make assertions about audit logs, but without an ID token.
				if test.wantAuditLogs != nil {
					wantAuditLogs := test.wantAuditLogs(actualSessionID, "")
					testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, "fake-token-exchange-audit-id")
					testutil.CompareAuditLogs(t, wantAuditLogs, actualAuditLog.String())
				}

				// The remaining assertions apply only to the happy path.
				return
			}

			claimsOfFirstIDToken := map[string]any{}
			originalIDToken := parsedAuthcodeExchangeResponseBody["id_token"].(string)
			firstIDTokenDecoded, _ := josejwt.ParseSigned(originalIDToken, []jose.SignatureAlgorithm{jose.ES256})
			err = firstIDTokenDecoded.UnsafeClaimsWithoutVerification(&claimsOfFirstIDToken)
			require.NoError(t, err)

			require.Contains(t, parsedResponseBody, "access_token")
			require.Equal(t, "N_A", parsedResponseBody["token_type"])
			require.Equal(t, "urn:ietf:params:oauth:token-type:jwt", parsedResponseBody["issued_token_type"])

			// Parse the returned token.
			actualIDToken := parsedResponseBody["access_token"].(string)
			parsedJWT, err := jose.ParseSigned(actualIDToken, []jose.SignatureAlgorithm{jose.ES256})
			require.NoError(t, err)
			var tokenClaims map[string]any
			require.NoError(t, json.Unmarshal(parsedJWT.UnsafePayloadWithoutVerification(), &tokenClaims))

			// Make sure that these are the only fields in the token.
			idTokenFields := []string{"sub", "aud", "iss", "jti", "auth_time", "exp", "iat", "rat", "username", "azp"}
			if test.authcodeExchange.want.wantGroups != nil {
				idTokenFields = append(idTokenFields, "groups")
			}
			if len(test.authcodeExchange.want.wantAdditionalClaims) > 0 {
				idTokenFields = append(idTokenFields, "additionalClaims")
			}
			require.ElementsMatch(t, idTokenFields, getMapKeys(tokenClaims))

			// Assert that the returned token has expected claims values.
			require.NotEmpty(t, tokenClaims["jti"])
			require.NotEmpty(t, tokenClaims["auth_time"])
			require.NotEmpty(t, tokenClaims["exp"])
			require.NotEmpty(t, tokenClaims["iat"])
			require.NotEmpty(t, tokenClaims["rat"])
			require.Len(t, tokenClaims["aud"], 1)
			require.Contains(t, tokenClaims["aud"], test.requestedAudience)
			require.Equal(t, test.authcodeExchange.want.wantClientID, tokenClaims["azp"])
			require.Equal(t, goodSubject, tokenClaims["sub"])
			require.Equal(t, goodIssuer, tokenClaims["iss"])
			if test.authcodeExchange.want.wantUsername != "" {
				require.Equal(t, test.authcodeExchange.want.wantUsername, tokenClaims["username"])
			} else {
				require.Nil(t, tokenClaims["username"])
			}
			if test.authcodeExchange.want.wantGroups != nil {
				require.Equal(t, toSliceOfInterface(test.authcodeExchange.want.wantGroups), tokenClaims["groups"])
			} else {
				require.Nil(t, tokenClaims["groups"])
			}

			if len(test.authcodeExchange.want.wantAdditionalClaims) > 0 {
				require.Equal(t, test.authcodeExchange.want.wantAdditionalClaims, tokenClaims["additionalClaims"])
			}
			additionalClaims, ok := tokenClaims["additionalClaims"].(map[string]any)
			if ok && tokenClaims["additionalClaims"] != nil {
				require.True(t, len(additionalClaims) > 0, "additionalClaims may never be present and empty in the id token")
			}

			// Also assert that some are the same as the original downstream ID token.
			requireClaimsAreEqual(t, "iss", claimsOfFirstIDToken, tokenClaims)       // issuer
			requireClaimsAreEqual(t, "sub", claimsOfFirstIDToken, tokenClaims)       // subject
			requireClaimsAreEqual(t, "rat", claimsOfFirstIDToken, tokenClaims)       // requested at
			requireClaimsAreEqual(t, "auth_time", claimsOfFirstIDToken, tokenClaims) // auth time
			if len(test.authcodeExchange.want.wantAdditionalClaims) > 0 {
				requireClaimsAreEqual(t, "additionalClaims", claimsOfFirstIDToken, tokenClaims)
			}

			// Also assert which are the different from the original downstream ID token.
			requireClaimsAreNotEqual(t, "jti", claimsOfFirstIDToken, tokenClaims) // JWT ID
			requireClaimsAreNotEqual(t, "aud", claimsOfFirstIDToken, tokenClaims) // audience
			requireClaimsAreNotEqual(t, "iat", claimsOfFirstIDToken, tokenClaims) // issued at
			require.Greater(t, tokenClaims["iat"], claimsOfFirstIDToken["iat"])
			requireClaimsAreNotEqual(t, "exp", claimsOfFirstIDToken, tokenClaims) // expires at
			if test.authcodeExchange.want.wantIDTokenLifetimeSeconds == 0 {
				// If the ID token lifetime of the original ID token was not customized by configuration,
				// then both the original and new ID tokens should have default 2-minute lifetimes, with the
				// clock starting for each at token issuing time. Therefore, the new one should expire
				// after the original one (i.e. a moving 2-minute window).
				require.Greater(t, tokenClaims["exp"], claimsOfFirstIDToken["exp"])
			}

			// Assert that the timestamps in the token are approximately as expected.
			// When dynamic clients are configured to have a custom ID token lifetime, that does not apply to
			// token exchanges. Therefore, we can always assert that the lifetime of the new ID token is always
			// the default lifetime.
			expiresAtAsFloat, ok := tokenClaims["exp"].(float64)
			require.True(t, ok, "expected exp claim to be a float64")
			expiresAt := time.Unix(int64(expiresAtAsFloat), 0)
			testutil.RequireTimeInDelta(t, approxRequestTime.UTC().Add(idTokenExpirationSeconds*time.Second), expiresAt, timeComparisonFudge)
			issuedAtAsFloat, ok := tokenClaims["iat"].(float64)
			require.True(t, ok, "expected iat claim to be a float64")
			issuedAt := time.Unix(int64(issuedAtAsFloat), 0)
			testutil.RequireTimeInDelta(t, approxRequestTime.UTC(), issuedAt, timeComparisonFudge)
			// The difference between iat (issued at) and exp (expires at) claims should be exactly the lifetime seconds.
			require.Equal(t, int64(idTokenExpirationSeconds), int64(expiresAtAsFloat)-int64(issuedAtAsFloat),
				"ID token lifetime was not the expected value")

			// Assert that nothing in storage has been modified.
			newSecrets, err := secrets.List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.ElementsMatch(t, existingSecrets.Items, newSecrets.Items)

			if test.wantAuditLogs != nil {
				wantAuditLogs := test.wantAuditLogs(actualSessionID, actualIDToken)
				testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, "fake-token-exchange-audit-id")
				testutil.CompareAuditLogs(t, wantAuditLogs, actualAuditLog.String())
			}
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

		githubUpstreamName        = "some-github-idp"
		githubUpstreamResourceUID = "github-resource-uid"
		githubUpstreamType        = "github"
		githubUpstreamAccessToken = "some-opaque-access-token-from-github" //nolint:gosec // this is not a credential

		transformationUsernamePrefix = "username_prefix:"
		transformationGroupsPrefix   = "groups_prefix:"
	)

	ldapUpstreamURL, _ := url.Parse("some-url")

	// The below values are funcs so every test can have its own copy of the objects, to avoid data races
	// in these parallel tests.

	upstreamOIDCIdentityProviderBuilder := func() *oidctestutil.TestUpstreamOIDCIdentityProviderBuilder {
		return oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
			WithName(oidcUpstreamName).
			WithResourceUID(oidcUpstreamResourceUID)
	}

	upstreamGitHubIdentityProviderBuilder := func() *oidctestutil.TestUpstreamGitHubIdentityProviderBuilder {
		goodGitHubUser := &upstreamprovider.GitHubUser{
			Username:          goodUsername,
			Groups:            goodGroups,
			DownstreamSubject: goodSubject,
		}
		return oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
			WithName(githubUpstreamName).
			WithResourceUID(githubUpstreamResourceUID).
			WithUser(goodGitHubUser)
	}

	initialUpstreamOIDCRefreshTokenCustomSessionData := func() *psession.CustomSessionData {
		return &psession.CustomSessionData{
			Username:         goodUsername,
			UpstreamUsername: goodUsername,
			UpstreamGroups:   goodGroups,
			ProviderName:     oidcUpstreamName,
			ProviderUID:      oidcUpstreamResourceUID,
			ProviderType:     oidcUpstreamType,
			OIDC: &psession.OIDCSessionData{
				UpstreamRefreshToken: oidcUpstreamInitialRefreshToken,
				UpstreamSubject:      goodUpstreamSubject,
				UpstreamIssuer:       goodIssuer,
			},
		}
	}

	initialUpstreamGitHubCustomSessionData := func() *psession.CustomSessionData {
		return &psession.CustomSessionData{
			Username:         goodUsername,
			UpstreamUsername: goodUsername,
			UpstreamGroups:   goodGroups,
			ProviderName:     githubUpstreamName,
			ProviderUID:      githubUpstreamResourceUID,
			ProviderType:     githubUpstreamType,
			GitHub: &psession.GitHubSessionData{
				UpstreamAccessToken: githubUpstreamAccessToken,
			},
		}
	}

	initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername := func(downstreamUsername string) *psession.CustomSessionData {
		customSessionData := initialUpstreamOIDCRefreshTokenCustomSessionData()
		customSessionData.Username = downstreamUsername
		return customSessionData
	}

	initialUpstreamOIDCAccessTokenCustomSessionData := func() *psession.CustomSessionData {
		return &psession.CustomSessionData{
			Username:         goodUsername,
			UpstreamUsername: goodUsername,
			UpstreamGroups:   goodGroups,
			ProviderName:     oidcUpstreamName,
			ProviderUID:      oidcUpstreamResourceUID,
			ProviderType:     oidcUpstreamType,
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

	upstreamOIDCCustomSessionDataWithNewRefreshTokenWithUsername := func(newRefreshToken string, downstreamUsername string) *psession.CustomSessionData {
		sessionData := initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(downstreamUsername)
		sessionData.OIDC.UpstreamRefreshToken = newRefreshToken
		return sessionData
	}

	happyOIDCUpstreamRefreshCall := func() *expectedOIDCUpstreamRefresh {
		return &expectedOIDCUpstreamRefresh{
			performedByUpstreamName: oidcUpstreamName,
			args: &oidctestutil.PerformOIDCRefreshArgs{
				Ctx:          nil, // this will be filled in with the actual request context by the test below
				RefreshToken: oidcUpstreamInitialRefreshToken,
			},
		}
	}

	happyGitHubUpstreamRefreshCall := func() *expectedGithubUpstreamRefresh {
		return &expectedGithubUpstreamRefresh{
			performedByUpstreamName: githubUpstreamName,
			args: &oidctestutil.GetUserArgs{
				Ctx:            nil, // this will be filled in with the actual request context by the test below
				AccessToken:    githubUpstreamAccessToken,
				IDPDisplayName: githubUpstreamName,
			},
		}
	}

	happyLDAPUpstreamRefreshCall := func() *expectedLDAPUpstreamRefresh {
		return &expectedLDAPUpstreamRefresh{
			performedByUpstreamName: ldapUpstreamName,
			args: &oidctestutil.PerformLDAPRefreshArgs{
				Ctx: nil, // this will be filled in with the actual request context by the test below
				StoredRefreshAttributes: upstreamprovider.LDAPRefreshAttributes{
					Username:             goodUsername,
					Subject:              goodSubject,
					DN:                   ldapUpstreamDN,
					Groups:               goodGroups,
					AdditionalAttributes: nil,
				},
				IDPDisplayName: ldapUpstreamName,
			},
		}
	}

	happyActiveDirectoryUpstreamRefreshCall := func() *expectedLDAPUpstreamRefresh {
		return &expectedLDAPUpstreamRefresh{
			performedByUpstreamName: activeDirectoryUpstreamName,
			args: &oidctestutil.PerformLDAPRefreshArgs{
				Ctx: nil, // this will be filled in with the actual request context by the test below
				StoredRefreshAttributes: upstreamprovider.LDAPRefreshAttributes{
					Username:             goodUsername,
					Subject:              goodSubject,
					DN:                   activeDirectoryUpstreamDN,
					Groups:               goodGroups,
					AdditionalAttributes: nil,
				},
				IDPDisplayName: activeDirectoryUpstreamName,
			},
		}
	}

	happyUpstreamValidateTokenCall := func(expectedTokens *oauth2.Token, requireIDToken bool) *expectedOIDCUpstreamValidateTokens {
		return &expectedOIDCUpstreamValidateTokens{
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
			wantClientID:                pinnipedCLIClientID,
			wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
			wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
			wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
			wantCustomSessionDataStored: wantCustomSessionDataStored,
			wantUsername:                goodUsername,
			wantGroups:                  goodGroups,
		}
		return want
	}

	happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups := func(wantCustomSessionDataStored *psession.CustomSessionData, wantDownstreamUsername string, wantDownsteamGroups []string) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		want.wantUsername = wantDownstreamUsername
		want.wantGroups = wantDownsteamGroups
		return want
	}

	withWantDynamicClientID := func(w tokenEndpointResponseExpectedValues) tokenEndpointResponseExpectedValues {
		w.wantClientID = dynamicClientID
		return w
	}

	modifyRefreshTokenRequestWithDynamicClientAuth := func(tokenRequest *http.Request, refreshToken string, accessToken string) {
		tokenRequest.Body = happyRefreshRequestBody(refreshToken).WithClientID("").ReadCloser() // No client_id in body.
		tokenRequest.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1)                 // Use basic auth header instead.
	}

	happyRefreshTokenResponseForOpenIDAndOfflineAccess := func(wantCustomSessionDataStored *psession.CustomSessionData, expectToValidateToken *oauth2.Token) tokenEndpointResponseExpectedValues {
		// Should always have some custom session data stored. The other expectations happens to be the
		// same as the same values as the authcode exchange case.
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		// Should always try to perform an upstream refresh.
		want.wantOIDCUpstreamRefreshCall = happyOIDCUpstreamRefreshCall()
		if expectToValidateToken != nil {
			want.wantUpstreamOIDCValidateTokenCall = happyUpstreamValidateTokenCall(expectToValidateToken, true)
		}
		return want
	}

	refreshResponseWithAuditLogs := func(expectedValues tokenEndpointResponseExpectedValues, wantAuditLogs func(sessionID string, idToken string) []testutil.WantedAuditLog) tokenEndpointResponseExpectedValues {
		expectedValues.wantAuditLogs = wantAuditLogs
		return expectedValues
	}

	happyRefreshTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups := func(wantCustomSessionDataStored *psession.CustomSessionData, expectToValidateToken *oauth2.Token, wantDownstreamUsername string, wantDownstreamGroups []string) tokenEndpointResponseExpectedValues {
		// Should always have some custom session data stored. The other expectations happens to be the
		// same as the same values as the authcode exchange case.
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(wantCustomSessionDataStored, wantDownstreamUsername, wantDownstreamGroups)
		// Should always try to perform an upstream refresh.
		want.wantOIDCUpstreamRefreshCall = happyOIDCUpstreamRefreshCall()
		if expectToValidateToken != nil {
			want.wantUpstreamOIDCValidateTokenCall = happyUpstreamValidateTokenCall(expectToValidateToken, true)
		}
		return want
	}

	happyRefreshTokenResponseForGitHubAndOfflineAccessWithUsernameAndGroups := func(wantCustomSessionDataStored *psession.CustomSessionData, wantDownstreamUsername string, wantDownstreamGroups []string) tokenEndpointResponseExpectedValues {
		// Should always have some custom session data stored. The other expectations happens to be the
		// same as the same values as the authcode exchange case.
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(wantCustomSessionDataStored, wantDownstreamUsername, wantDownstreamGroups)
		// Should always try to perform an upstream refresh.
		want.wantGithubUpstreamRefreshCall = happyGitHubUpstreamRefreshCall()
		return want
	}

	happyRefreshTokenResponseForOpenIDAndOfflineAccessWithAdditionalClaims := func(wantCustomSessionDataStored *psession.CustomSessionData, expectToValidateToken *oauth2.Token, wantAdditionalClaims map[string]any) tokenEndpointResponseExpectedValues {
		want := happyRefreshTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored, expectToValidateToken)
		want.wantAdditionalClaims = wantAdditionalClaims
		return want
	}

	happyRefreshTokenResponseForLDAP := func(wantCustomSessionDataStored *psession.CustomSessionData) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		want.wantLDAPUpstreamRefreshCall = happyLDAPUpstreamRefreshCall()
		return want
	}

	happyRefreshTokenResponseForLDAPWithUsernameAndGroups := func(wantCustomSessionDataStored *psession.CustomSessionData, wantDownstreamUsername string, wantDownstreamGroups []string) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(wantCustomSessionDataStored, wantDownstreamUsername, wantDownstreamGroups)
		want.wantLDAPUpstreamRefreshCall = happyLDAPUpstreamRefreshCall()
		return want
	}

	happyRefreshTokenResponseForActiveDirectory := func(wantCustomSessionDataStored *psession.CustomSessionData) tokenEndpointResponseExpectedValues {
		want := happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(wantCustomSessionDataStored)
		want.wantActiveDirectoryUpstreamRefreshCall = happyActiveDirectoryUpstreamRefreshCall()
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
			WithExtra(map[string]any{"id_token": oidcUpstreamRefreshedIDToken})
	}

	refreshedUpstreamTokensWithIDTokenWithoutRefreshToken := func() *oauth2.Token {
		tokens := refreshedUpstreamTokensWithIDAndRefreshTokens()
		tokens.RefreshToken = "" // remove the refresh token
		return tokens
	}

	happyActiveDirectoryCustomSessionData := &psession.CustomSessionData{
		Username:         goodUsername,
		UpstreamUsername: goodUsername,
		UpstreamGroups:   goodGroups,
		ProviderUID:      activeDirectoryUpstreamResourceUID,
		ProviderName:     activeDirectoryUpstreamName,
		ProviderType:     activeDirectoryUpstreamType,
		ActiveDirectory: &psession.ActiveDirectorySessionData{
			UserDN: activeDirectoryUpstreamDN,
		},
	}

	happyLDAPCustomSessionData := &psession.CustomSessionData{
		Username:         goodUsername,
		UpstreamUsername: goodUsername,
		UpstreamGroups:   goodGroups,
		ProviderUID:      ldapUpstreamResourceUID,
		ProviderName:     ldapUpstreamName,
		ProviderType:     ldapUpstreamType,
		LDAP: &psession.LDAPSessionData{
			UserDN: ldapUpstreamDN,
		},
	}

	happyLDAPCustomSessionDataWithUsername := func(wantDownstreamUsername string) *psession.CustomSessionData {
		copyOfCustomSession := *happyLDAPCustomSessionData
		copyOfLDAP := *(happyLDAPCustomSessionData.LDAP)
		copyOfCustomSession.LDAP = &copyOfLDAP
		copyOfCustomSession.Username = wantDownstreamUsername
		return &copyOfCustomSession
	}

	happyAuthcodeExchangeInputsForOIDCUpstream := authcodeExchangeInputs{
		modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
		customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
		want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
			initialUpstreamOIDCRefreshTokenCustomSessionData(),
		),
	}

	happyAuthcodeExchangeInputsForGithubUpstream := authcodeExchangeInputs{
		modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
		customSessionData: initialUpstreamGitHubCustomSessionData(),
		want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
			initialUpstreamGitHubCustomSessionData(),
		),
	}

	happyAuthcodeExchangeInputsForLDAPUpstream := authcodeExchangeInputs{
		modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
		customSessionData: happyLDAPCustomSessionData,
		want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
			happyLDAPCustomSessionData,
		),
	}

	prefixUsernameAndGroupsPipeline := transformtestutil.NewPrefixingPipeline(t, transformationUsernamePrefix, transformationGroupsPrefix)
	rejectAuthPipeline := transformtestutil.NewRejectAllAuthPipeline(t)

	tests := []struct {
		name                      string
		idps                      *testidplister.UpstreamIDPListerBuilder
		kubeResources             func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset)
		authcodeExchange          authcodeExchangeInputs
		refreshRequest            refreshRequestInputs
		modifyRefreshTokenStorage func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string)
	}{
		{
			name: "happy path refresh grant with openid scope granted (id token returned)",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: refreshResponseWithAuditLogs(
					happyRefreshTokenResponseForOpenIDAndOfflineAccess(
						upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
						refreshedUpstreamTokensWithIDAndRefreshTokens(),
					),
					func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"grant_type":    "refresh_token",
									"refresh_token": "redacted",
									"scope":         "openid",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("Identity Refreshed From Upstream IDP", map[string]any{
								"sessionID": sessionID,
								"personalInfo": map[string]any{
									"upstreamGroups":   []any{},
									"upstreamUsername": "some-username",
								},
							}),
							testutil.WantAuditLog("Session Refreshed", map[string]any{
								"sessionID": sessionID,
								"personalInfo": map[string]any{
									"username": "some-username",
									"groups": []any{
										"group1",
										"groups2",
									},
									"subject": "https://issuer?sub=some-subject",
								},
							}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "567 Bytes", // the token contents may be random, but the size is predictable
							}),
						}
					},
				),
			},
		},
		{
			name: "happy path refresh grant with OIDC upstream with identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
					WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					session.IDTokenClaims().Extra["username"] = transformationUsernamePrefix + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					upstreamOIDCCustomSessionDataWithNewRefreshTokenWithUsername(oidcUpstreamRefreshedRefreshToken, transformationUsernamePrefix+goodUsername),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
		},
		{
			name: "happy path refresh grant with GitHub upstream",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(
				upstreamGitHubIdentityProviderBuilder().Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForGithubUpstream,
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForGitHubAndOfflineAccessWithUsernameAndGroups(
					initialUpstreamGitHubCustomSessionData(),
					goodUsername,
					goodGroups,
				),
			},
		},
		{
			name: "happy path refresh grant with OIDC upstream with identity transformations which modify the username and group names when the upstream refresh does not return new username or groups then it reruns the transformations on the old upstream username and groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken()).
					WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					session.IDTokenClaims().Extra["username"] = transformationUsernamePrefix + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      transformationUsernamePrefix + goodUsername,
					wantGroups:                        testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken(), false),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshTokenWithUsername(oidcUpstreamRefreshedRefreshToken, transformationUsernamePrefix+goodUsername),
				},
			},
		},
		{
			name: "refresh grant with OIDC upstream with identity transformations which modify the username and group names when the downstream username has changed compared to initial login",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
					WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).Build()),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername("some_other_transform_prefix:" + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					session.IDTokenClaims().Extra["username"] = "some_other_transform_prefix:" + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername("some_other_transform_prefix:"+goodUsername),
					"some_other_transform_prefix:"+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			name: "refresh grant with OIDC upstream with identity transformations which reject the auth",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
					WithTransformsForFederationDomain(rejectAuthPipeline).Build()),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					session.IDTokenClaims().Extra["username"] = transformationUsernamePrefix + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					initialUpstreamOIDCRefreshTokenCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh rejected by configured identity policy: authentication was rejected by a configured policy."
						}
					`),
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"grant_type":    "refresh_token",
									"refresh_token": "redacted",
									"scope":         "openid",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("Identity Refreshed From Upstream IDP", map[string]any{
								"sessionID": sessionID,
								"personalInfo": map[string]any{
									"upstreamGroups":   []any{},
									"upstreamUsername": "some-username",
								},
							}),
							testutil.WantAuditLog("Authentication Rejected By Transforms", map[string]any{
								"sessionID": sessionID,
								"reason":    "Upstream refresh rejected by configured identity policy: authentication was rejected by a configured policy.",
							}),
						}
					},
				},
			},
		},
		{
			name: "happy path refresh grant with openid scope granted (id token returned) and additionalClaims",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
					}
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"code":          "redacted",
									"code_verifier": "redacted",
									"grant_type":    "authorization_code",
									"redirect_uri":  "http://127.0.0.1/callback",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "886 Bytes", // the token contents may be random, but the size is predictable
							}),
						}
					},
				},
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccessWithAdditionalClaims(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
					map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				),
			},
		},
		{
			name: "happy path refresh grant with openid scope granted (id token returned) using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData())),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: withWantDynamicClientID(happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				)),
			},
		},
		{
			name: "happy path refresh grant with openid scope granted (id token returned) using dynamic client which has custom ID token lifetime configured",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientWithCustomIDTokenLifetimeAndSecretToKubeResources(4242),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: withWantCustomIDTokenLifetime(4242,
					withWantDynamicClientID(
						happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData()),
					),
				),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: withWantCustomIDTokenLifetime(4242,
					withWantDynamicClientID(
						happyRefreshTokenResponseForOpenIDAndOfflineAccess(
							upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
							refreshedUpstreamTokensWithIDAndRefreshTokens(),
						),
					),
				),
			},
		},
		{
			name: "happy path refresh grant with openid scope granted (id token returned) using dynamic client with additional claims",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifySession: func(session *psession.PinnipedSession) {
					session.IDTokenClaims().Extra["additionalClaims"] = map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999,
						"upstreamObj": map[string]string{
							"name": "value",
						},
					}
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
					wantAdditionalClaims: map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: withWantDynamicClientID(happyRefreshTokenResponseForOpenIDAndOfflineAccessWithAdditionalClaims(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
					map[string]any{
						"upstreamString": "string value",
						"upstreamBool":   true,
						"upstreamArray":  []any{"hello", true},
						"upstreamFloat":  42.0,
						"upstreamInt":    999.0, // note: this is deserialized as float64
						"upstreamObj": map[string]any{
							"name": "value",
						},
					},
				)),
			},
		},
		{
			name: "happy path refresh grant with upstream username claim but without downstream username scope granted, using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"some-claim":     "some-value",
							"sub":            goodUpstreamSubject,
							"username-claim": goodUsername,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want: withWantDynamicClientID(tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                "",
					wantGroups:                  goodGroups,
				}),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: withWantDynamicClientID(tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      dynamicClientID,
					wantSuccessBodyFields:             []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "groups"},
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantUsername:                      "",
					wantGroups:                        goodGroups,
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
				}),
			},
		},
		{
			name: "refresh grant with unchanged username claim",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"some-claim":     "some-value",
							"sub":            goodUpstreamSubject,
							"username-claim": goodUsername,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					refreshedUpstreamTokensWithIDAndRefreshTokens(),
				),
			},
		},
		{
			name: "refresh grant when the customsessiondata has a stored access token and no stored refresh token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").
					WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Claims: map[string]any{
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
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				want:              happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCAccessTokenCustomSessionData()),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusOK,
					wantClientID:          pinnipedCLIClientID,
					wantSuccessBodyFields: []string{"refresh_token", "id_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:   []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:     []string{"openid", "offline_access", "username", "groups"},
					wantUsername:          goodUsername,
					wantGroups:            goodGroups,
					wantUpstreamOIDCValidateTokenCall: &expectedOIDCUpstreamValidateTokens{
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access"},
					wantGrantedScopes:           []string{"offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"offline_access"},
					wantGrantedScopes:                 []string{"offline_access", "username", "groups"},
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken(), false),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantUsername:                      goodUsername,
					wantGroups:                        goodGroups,
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return a new ID token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        goodGroups,
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithRefreshTokenWithoutIDToken(), false),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships (as strings) from the merged ID token and userinfo results, it updates groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
					wantAuditLogs: func(sessionID string, idToken string) []testutil.WantedAuditLog {
						return []testutil.WantedAuditLog{
							testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
								"params": map[string]any{
									"client_id":     "pinniped-cli",
									"grant_type":    "refresh_token",
									"refresh_token": "redacted",
									"scope":         "openid",
								},
							}),
							testutil.WantAuditLog("Session Found", map[string]any{"sessionID": sessionID}),
							testutil.WantAuditLog("Identity Refreshed From Upstream IDP", map[string]any{
								"sessionID": sessionID,
								"personalInfo": map[string]any{
									"upstreamGroups": []any{
										"new-group1",
										"new-group2",
										"new-group3",
									},
									"upstreamUsername": "some-username",
								},
							}),
							testutil.WantAuditLog("Session Refreshed", map[string]any{
								"sessionID": sessionID,
								"personalInfo": map[string]any{
									"username": "some-username",
									"groups": []any{
										"new-group1",
										"new-group2",
										"new-group3",
									},
									"subject": "https://issuer?sub=some-subject",
								},
							}),
							testutil.WantAuditLog("ID Token Issued", map[string]any{
								"sessionID": sessionID,
								"tokenID":   idTokenToHash(idToken),
								"tokenSize": "594 Bytes", // the token contents may be random, but the size is predictable
							}),
						}
					},
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships (as strings) from the merged ID token and userinfo results, it updates groups, using dynamic client - updates groups without outputting warnings",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData())),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      dynamicClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantWarnings:                      nil, // dynamic clients should not get these warnings which are intended for the pinniped-cli client
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships (as any types) from the merged ID token and userinfo results, it updates groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []any{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships as an empty list from the merged ID token and userinfo results, it updates groups to be empty",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{}, // refreshed groups claims is updated to be an empty list
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        []string{}, // the user no longer belongs to any groups
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return new group memberships from the merged ID token and userinfo results by omitting claim, it keeps groups from initial login",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
							// "my-groups-claim" is omitted from the refreshed claims
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        goodGroups, // the same groups as from the initial login
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships from LDAP, it updates groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups([]string{"new-group1", "new-group2", "new-group3"}).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                goodUsername,
					wantGroups:                  []string{"new-group1", "new-group2", "new-group3"},
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships from LDAP, it updates groups, using dynamic client - updates groups without outputting warnings",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups([]string{"new-group1", "new-group2", "new-group3"}).
				Build(),
			),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: happyLDAPCustomSessionData,
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(happyLDAPCustomSessionData)),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                goodUsername,
					wantGroups:                  []string{"new-group1", "new-group2", "new-group3"},
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantWarnings:                nil, // dynamic clients should not get these warnings which are intended for the pinniped-cli client
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships from GitHub, it updates groups",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
				WithName(githubUpstreamName).
				WithResourceUID(githubUpstreamResourceUID).
				WithUser(&upstreamprovider.GitHubUser{
					Username:          goodUsername,
					Groups:            []string{goodGroups[0], "new-group1", "new-group2", "new-group3"},
					DownstreamSubject: goodSubject,
				}).Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForGithubUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                    http.StatusOK,
					wantClientID:                  pinnipedCLIClientID,
					wantSuccessBodyFields:         []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:             []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                  goodUsername,
					wantGroups:                    []string{goodGroups[0], "new-group1", "new-group2", "new-group3"},
					wantGithubUpstreamRefreshCall: happyGitHubUpstreamRefreshCall(),
					wantCustomSessionDataStored:   initialUpstreamGitHubCustomSessionData(),
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["groups2"]`},
					},
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns new group memberships from GitHub, it updates groups, using dynamic client - updates groups without outputting warnings",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
				WithName(githubUpstreamName).
				WithResourceUID(githubUpstreamResourceUID).
				WithUser(&upstreamprovider.GitHubUser{
					Username:          goodUsername,
					Groups:            []string{goodGroups[0], "new-group1", "new-group2", "new-group3"},
					DownstreamSubject: goodSubject,
				}).Build(),
			),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamGitHubCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamGitHubCustomSessionData())),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                    http.StatusOK,
					wantClientID:                  dynamicClientID,
					wantSuccessBodyFields:         []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:             []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                  goodUsername,
					wantGroups:                    []string{goodGroups[0], "new-group1", "new-group2", "new-group3"},
					wantGithubUpstreamRefreshCall: happyGitHubUpstreamRefreshCall(),
					wantCustomSessionDataStored:   initialUpstreamGitHubCustomSessionData(),
					wantWarnings:                  nil, // dynamic clients should not get these warnings which are intended for the pinniped-cli client
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh returns empty list of group memberships from LDAP, it updates groups to an empty list",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups([]string{}).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                goodUsername,
					wantGroups:                  []string{},
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "ldap refresh grant when the upstream refresh when username and groups scopes are not requested on original request or refresh",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups([]string{"new-group1", "new-group2", "new-group3"}).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: happyLDAPCustomSessionData,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid offline_access").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:                goodUsername,
					wantGroups:                  []string{"new-group1", "new-group2", "new-group3"},
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "oidc refresh grant when the upstream refresh when username and groups scopes are not requested on original request or refresh",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access") },
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid offline_access").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username", "groups"}, // username and groups were not requested, but granted anyway for backwards compatibility
					wantUsername:                      goodUsername,
					wantGroups:                        []string{"new-group1", "new-group2", "new-group3"},
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "oidc refresh grant when the upstream refresh when groups scope not requested on original request or refresh when using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				customSessionData:  initialUpstreamOIDCRefreshTokenCustomSessionData(),
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  nil,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithClientID("").WithScope("openid offline_access username").ReadCloser()
					r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1) // Use basic auth header instead.
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusOK,
					wantClientID:                      dynamicClientID,
					wantSuccessBodyFields:             []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "username"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "username"},
					wantUsername:                      goodUsername,
					wantGroups:                        nil,
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "refresh grant when the upstream refresh when groups scope not requested on original request, when using dynamic client, " +
				"still runs identity transformations with upstream groups in case transforms want to reject auth based on groups, even though groups would not be included in final ID token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": []string{"new-group1", "new-group2", "new-group3"}, // refreshed claims includes updated groups
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
					WithTransformsForFederationDomain(transformtestutil.NewPipeline(t,
						[]celtransformer.CELTransformation{
							&celtransformer.AllowAuthenticationPolicy{
								Expression:                    `!groups.exists(g, g in ["` + "new-group1" + `"])`, // reject auth for users who belongs to an upstream group
								RejectedAuthenticationMessage: `users who belong to certain upstream group are not allowed`,
							},
						}),
					).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				customSessionData:  initialUpstreamOIDCRefreshTokenCustomSessionData(),
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  nil,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithClientID("").WithScope("openid offline_access username").ReadCloser()
					r.SetBasicAuth(dynamicClientID, testutil.PlaintextPassword1) // Use basic auth header instead.
				},
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantStatus:                        http.StatusUnauthorized,
					// auth was rejected because of the upstream group to which the user belonged, as shown by the configured RejectedAuthenticationMessage appearing here
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh rejected by configured identity policy: users who belong to certain upstream group are not allowed."
						}
					`),
				},
			},
		},
		{
			// fosite does not look at the scopes provided in refresh requests, although it is a valid parameter.
			// even if 'groups' is not sent in the refresh request, we will send groups all the same.
			name: "refresh grant when the upstream refresh when groups scope requested on original request but not refresh refresh",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups([]string{"new-group1", "new-group2", "new-group3"}).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionData,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithScope("openid offline_access").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "id_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "username", "groups"},
					wantUsername:                goodUsername,
					wantGroups:                  []string{"new-group1", "new-group2", "new-group3"}, // groups are updated even though the scope was not included
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantWarnings: []RecordedWarning{
						{Text: `User "some-username" has been added to the following groups: ["new-group1" "new-group2" "new-group3"]`},
						{Text: `User "some-username" has been removed from the following groups: ["group1" "groups2"]`},
					},
				},
			},
		},
		{
			name: "error from refresh grant when the upstream refresh does not return new group memberships from the merged ID token and userinfo results by returning group claim with illegal nil value",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithGroupsClaim("my-groups-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub":             goodUpstreamSubject,
							"my-groups-claim": nil,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                        http.StatusUnauthorized,
					wantErrorResponseBody:             fositeUpstreamGroupClaimErrorBody,
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
				},
			},
		},
		{
			name: "happy path refresh grant when the upstream refresh does not return a new refresh token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDTokenWithoutRefreshToken()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForOpenIDAndOfflineAccess(
					initialUpstreamOIDCRefreshTokenCustomSessionData(), // still has the initial refresh token stored
					refreshedUpstreamTokensWithIDTokenWithoutRefreshToken(),
				),
			},
		},
		{
			name: "when the refresh request adds a new scope to the list of requested scopes then it is ignored",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					r.Form.Set("scope", "openid offline_access pinniped:request-audience username groups")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
					wantUsername:                goodUsername,
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
					wantClientID:                      pinnipedCLIClientID,
					wantSuccessBodyFields:             []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:               []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
					wantGrantedScopes:                 []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
					wantUsername:                      goodUsername,
					wantGroups:                        goodGroups,
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
					wantUpstreamOIDCValidateTokenCall: happyUpstreamValidateTokenCall(refreshedUpstreamTokensWithIDAndRefreshTokens(), true),
					wantCustomSessionDataStored:       upstreamOIDCCustomSessionDataWithNewRefreshToken(oidcUpstreamRefreshedRefreshToken),
				},
			},
		},
		{
			name: "when the refresh request does not include a scope param then it gets all the same scopes as the original authorization request",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
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
			name:             "when a valid refresh token is sent in the refresh request, but the token has already expired",
			idps:             testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string) {
				// The fosite storage APIs don't offer a way to update a refresh token, so we will instead find the underlying
				// storage Secret and update it in a more manual way. First get the refresh token's signature.
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				// Find the storage Secret for the refresh token by using its signature to compute the Secret name.
				refreshTokenSecretName := getSecretNameFromSignature(t, refreshTokenSignature, "refresh-token") // "refresh-token" is the storage type used in the Secret's name
				refreshTokenSecret, err := secrets.Get(context.Background(), refreshTokenSecretName, metav1.GetOptions{})
				require.NoError(t, err)
				// Parse the session from the storage Secret.
				savedSessionJSON := refreshTokenSecret.Data["pinniped-storage-data"]
				// Declare the appropriate empty struct, similar to how our kubestorage implementation
				// of GetRefreshTokenSession() does when parsing a session from a storage Secret.
				refreshTokenSession := &refreshtoken.Session{
					Request: &fosite.Request{
						Client:  &clientregistry.Client{},
						Session: &psession.PinnipedSession{},
					},
				}
				// Parse the session JSON and fill the empty struct with its data.
				err = json.Unmarshal(savedSessionJSON, refreshTokenSession)
				require.NoError(t, err)
				// Change the refresh token's expiration time to be one hour ago, so it will be considered already expired.
				oneHourAgoInUTC := time.Now().UTC().Add(-1 * time.Hour)
				refreshTokenSession.Request.Session.(*psession.PinnipedSession).Fosite.SetExpiresAt(fosite.RefreshToken, oneHourAgoInUTC)
				// Write the updated session back to the refresh token's storage Secret.
				updatedSessionJSON, err := json.Marshal(refreshTokenSession)
				require.NoError(t, err)
				refreshTokenSecret.Data["pinniped-storage-data"] = updatedSessionJSON
				_, err = secrets.Update(context.Background(), refreshTokenSecret, metav1.UpdateOptions{})
				require.NoError(t, err)
				// Just to be sure that this test setup is valid, confirm that the code above correctly updated the
				// refresh token's expiration time by reading it again, this time performing the read using the
				// kubestorage API instead of the manual/direct approach used above.
				session, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				expiresAt := session.GetSession().GetExpiresAt(fosite.RefreshToken)
				require.Equal(t, oneHourAgoInUTC, expiresAt)
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeExpiredRefreshTokenErrorBody,
				},
			},
		},
		{
			name: "when a bad refresh token is sent in the refresh request",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"offline_access", "username", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken("bad refresh token").ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRefreshTokenErrorBody,
				},
			},
		},
		{
			name: "when the access token is sent as if it were a refresh token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"offline_access", "username", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
				},
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(r *http.Request, refreshToken string, accessToken string) {
					r.Body = happyRefreshRequestBody(refreshToken).WithRefreshToken(accessToken).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeInvalidRefreshTokenErrorBody,
				},
			},
		},
		{
			name: "when the wrong client ID is included in the refresh request",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "offline_access username groups") },
				want: tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                pinnipedCLIClientID,
					wantSuccessBodyFields:       []string{"refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"offline_access", "username", "groups"},
					wantGrantedScopes:           []string{"offline_access", "username", "groups"},
					wantCustomSessionDataStored: initialUpstreamOIDCRefreshTokenCustomSessionData(),
					wantUsername:                goodUsername,
					wantGroups:                  goodGroups,
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
			name: "when the refresh request uses a different client than the one that was used to get the refresh token",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources:    addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream, // Make the auth request and authcode exchange request using the pinniped-cli client.
			refreshRequest: refreshRequestInputs{
				// Make the refresh request with the dynamic client.
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusBadRequest,
					wantErrorResponseBody: fositeClientIDMismatchDuringRefreshErrorBody,
				},
			},
		},
		{
			name: "when the client auth fails on the refresh request using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData())),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(tokenRequest *http.Request, refreshToken string, accessToken string) {
					tokenRequest.Body = happyRefreshRequestBody(refreshToken).WithClientID("").ReadCloser()
					tokenRequest.SetBasicAuth(dynamicClientID, "wrong client secret")
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeClientAuthFailedErrorBody,
				},
			},
		},
		{
			name: "dynamic client uses wrong auth method on the refresh request (must use basic auth)",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": goodUpstreamSubject,
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: initialUpstreamOIDCRefreshTokenCustomSessionData(),
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(initialUpstreamOIDCRefreshTokenCustomSessionData())),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: func(tokenRequest *http.Request, refreshToken string, accessToken string) {
					// Add client auth to the form, when it should be in basic auth headers.
					tokenRequest.Body = happyRefreshRequestBody(refreshToken).WithClientID(dynamicClientID).WithClientSecret(testutil.PlaintextPassword1).ReadCloser()
				},
				want: tokenEndpointResponseExpectedValues{
					wantStatus:            http.StatusUnauthorized,
					wantErrorResponseBody: fositeClientAuthMustBeBasicAuthErrorBody,
				},
			},
		},
		{
			name: "when there is no custom session data found in the session storage during the refresh request",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: nil, // this should not happen in practice
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: "", // this should not happen in practice
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  "", // this should not happen in practice
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: "", // this should not happen in practice
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: "not-an-allowed-provider-type", // this should not happen in practice
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					ProviderName: oidcUpstreamName,
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         nil, // this should not happen in practice
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
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
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					Username:     goodUsername,
					ProviderName: "this-name-will-not-be-found", // this could happen if the OIDCIdentityProvider was deleted since original login
					ProviderUID:  oidcUpstreamResourceUID,
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						Username:     goodUsername,
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().Build()),
			authcodeExchange: authcodeExchangeInputs{
				customSessionData: &psession.CustomSessionData{
					Username:     goodUsername,
					ProviderName: oidcUpstreamName,
					ProviderUID:  "this is the wrong uid", // this could happen if the OIDCIdentityProvider was deleted and recreated at the same name since original login
					ProviderType: oidcUpstreamType,
					OIDC:         &psession.OIDCSessionData{UpstreamRefreshToken: oidcUpstreamInitialRefreshToken},
				},
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					&psession.CustomSessionData{ // want the initial customSessionData to be unmodified
						Username:     goodUsername,
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
			name: "when the upstream refresh fails during the refresh request using OIDC upstream",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithPerformRefreshError(errors.New("some upstream refresh error")).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall: happyOIDCUpstreamRefreshCall(),
					wantStatus:                  http.StatusUnauthorized,
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
			name: "when the upstream refresh fails during the refresh request using GitHub upstream",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithGitHub(upstreamGitHubIdentityProviderBuilder().
				WithGetUserError(errors.New("some upstream refresh error")).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForGithubUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantGithubUpstreamRefreshCall: happyGitHubUpstreamRefreshCall(),
					wantStatus:                    http.StatusUnauthorized,
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
				// This is the current format of the errors returned by the production code version of ValidateTokenAndMergeWithUserInfo, see ValidateTokenAndMergeWithUserInfo in upstreamoidc.go
				WithValidateTokenAndMergeWithUserInfoError(httperr.Wrap(http.StatusBadRequest, "some validate error", errors.New("some validate cause"))).
				Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(upstreamOIDCIdentityProviderBuilder().
				WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).
				// This is the current format of the errors returned by the production code version of ValidateTokenAndMergeWithUserInfo, see ValidateTokenAndMergeWithUserInfo in upstreamoidc.go
				WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"sub": "something-different",
						},
					},
				}).
				Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"some-claim": "some-value",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"some-claim":     "some-value",
							"sub":            goodUpstreamSubject,
							"username-claim": "some-changed-username",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithOIDC(
				upstreamOIDCIdentityProviderBuilder().WithUsernameClaim("username-claim").WithValidatedAndMergedWithUserInfoTokens(&oidctypes.Token{
					IDToken: &oidctypes.IDToken{
						Claims: map[string]any{
							"some-claim": "some-value",
							"sub":        goodUpstreamSubject,
							"iss":        "some-changed-issuer",
						},
					},
				}).WithRefreshedTokens(refreshedUpstreamTokensWithIDAndRefreshTokens()).Build()),
			authcodeExchange: happyAuthcodeExchangeInputsForOIDCUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantOIDCUpstreamRefreshCall:       happyOIDCUpstreamRefreshCall(),
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForLDAP(
					happyLDAPCustomSessionData,
				),
			},
		},
		{
			name: "upstream ldap refresh happy path with identity transformations which modify the username and group names",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionDataWithUsername(transformationUsernamePrefix + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					session.IDTokenClaims().Extra["username"] = transformationUsernamePrefix + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					happyLDAPCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: happyRefreshTokenResponseForLDAPWithUsernameAndGroups(
					happyLDAPCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
		},
		{
			name: "upstream ldap refresh with identity transformations which modify the username and group names when the downstream username has changed compared to initial login",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				WithTransformsForFederationDomain(prefixUsernameAndGroupsPipeline).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionDataWithUsername("some_other_transform_prefix:" + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					// In this case we will simulate a successful auth so we can test what happens when the refresh is
					// rejected by the identity transformations.
					session.IDTokenClaims().Extra["username"] = "some_other_transform_prefix:" + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					happyLDAPCustomSessionDataWithUsername("some_other_transform_prefix:"+goodUsername),
					"some_other_transform_prefix:"+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantStatus:                  http.StatusUnauthorized,
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
			name: "upstream ldap refresh with identity transformations which reject the auth",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				WithTransformsForFederationDomain(rejectAuthPipeline).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionDataWithUsername(transformationUsernamePrefix + goodUsername),
				modifySession: func(session *psession.PinnipedSession) {
					// The authorization flow would have run the transformation pipeline and stored the transformed
					// downstream identity in this part of the session, so simulate that by setting the expected result.
					// In this case we will simulate a successful auth so we can test what happens when the refresh is
					// rejected by the identity transformations.
					session.IDTokenClaims().Extra["username"] = transformationUsernamePrefix + goodUsername
					session.IDTokenClaims().Extra["groups"] = testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups)
				},
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccessWithUsernameAndGroups(
					happyLDAPCustomSessionDataWithUsername(transformationUsernamePrefix+goodUsername),
					transformationUsernamePrefix+goodUsername,
					testutil.AddPrefixToEach(transformationGroupsPrefix, goodGroups),
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantStatus:                  http.StatusUnauthorized,
					wantErrorResponseBody: here.Doc(`
						{
							"error":             "error",
							"error_description": "Error during upstream refresh. Upstream refresh rejected by configured identity policy: authentication was rejected by a configured policy."
						}
					`),
				},
			},
		},
		{
			name: "upstream ldap refresh happy path using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				Build(),
			),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access username groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				customSessionData:  happyLDAPCustomSessionData,
				want:               withWantDynamicClientID(happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(happyLDAPCustomSessionData)),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want:               withWantDynamicClientID(happyRefreshTokenResponseForLDAP(happyLDAPCustomSessionData)),
			},
		},
		{
			name: "upstream ldap refresh happy path without downstream username scope granted, using dynamic client",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				Build(),
			),
			kubeResources: addFullyCapableDynamicClientAndSecretToKubeResources,
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) {
					addDynamicClientIDToFormPostBody(r)
					r.Form.Set("scope", "openid offline_access groups")
				},
				modifyTokenRequest: modifyAuthcodeTokenRequestWithDynamicClientAuth,
				customSessionData:  happyLDAPCustomSessionData,
				want: withWantDynamicClientID(tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "groups"},
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantUsername:                "",
					wantGroups:                  goodGroups,
				}),
			},
			refreshRequest: refreshRequestInputs{
				modifyTokenRequest: modifyRefreshTokenRequestWithDynamicClientAuth,
				want: withWantDynamicClientID(tokenEndpointResponseExpectedValues{
					wantStatus:                  http.StatusOK,
					wantClientID:                dynamicClientID,
					wantSuccessBodyFields:       []string{"id_token", "refresh_token", "access_token", "token_type", "expires_in", "scope"},
					wantRequestedScopes:         []string{"openid", "offline_access", "groups"},
					wantGrantedScopes:           []string{"openid", "offline_access", "groups"},
					wantCustomSessionDataStored: happyLDAPCustomSessionData,
					wantUsername:                "",
					wantGroups:                  goodGroups,
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
				}),
			},
		},
		{
			name: "upstream active directory refresh happy path",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(activeDirectoryUpstreamName).
				WithResourceUID(activeDirectoryUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshGroups(goodGroups).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(activeDirectoryUpstreamName).
				WithResourceUID(activeDirectoryUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(activeDirectoryUpstreamName).
				WithResourceUID(activeDirectoryUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshErr(errors.New("Some error performing upstream refresh")).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantLDAPUpstreamRefreshCall: happyLDAPUpstreamRefreshCall(),
					wantStatus:                  http.StatusUnauthorized,
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(activeDirectoryUpstreamName).
				WithResourceUID(activeDirectoryUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				WithPerformRefreshErr(errors.New("Some error performing upstream refresh")).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyActiveDirectoryCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyActiveDirectoryCustomSessionData,
				),
			},
			refreshRequest: refreshRequestInputs{
				want: tokenEndpointResponseExpectedValues{
					wantActiveDirectoryUpstreamRefreshCall: happyActiveDirectoryUpstreamRefreshCall(),
					wantStatus:                             http.StatusUnauthorized,
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
			name:             "upstream ldap idp not found",
			idps:             testidplister.NewUpstreamIDPListerBuilder(),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
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
			idps: testidplister.NewUpstreamIDPListerBuilder(),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Fosite = &openid.DefaultSession{}
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, "ignored", firstRequester)
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
			name: "groups not found in extra field when the groups scope was granted",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				delete(session.Fosite.Claims.Extra, "groups")
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, "ignored", firstRequester)
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
			name: "username in custom session is empty string during refresh",
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
				customSessionData: happyLDAPCustomSessionData,
				want: happyAuthcodeExchangeTokenResponseForOpenIDAndOfflineAccess(
					happyLDAPCustomSessionData,
				),
			},
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				session.Custom.Username = ""
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, "ignored", firstRequester)
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID("the-wrong-uid").
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
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
			idps: testidplister.NewUpstreamIDPListerBuilder().WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(activeDirectoryUpstreamName).
				WithResourceUID("the-wrong-uid").
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: authcodeExchangeInputs{
				modifyAuthRequest: func(r *http.Request) { r.Form.Set("scope", "openid offline_access username groups") },
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
			name: "auth time is the zero value", // time.Times can never be nil, but it is possible that it would be the zero value which would mean something's wrong
			idps: testidplister.NewUpstreamIDPListerBuilder().WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
				WithName(ldapUpstreamName).
				WithResourceUID(ldapUpstreamResourceUID).
				WithURL(ldapUpstreamURL).
				Build(),
			),
			authcodeExchange: happyAuthcodeExchangeInputsForLDAPUpstream,
			modifyRefreshTokenStorage: func(t *testing.T, oauthStore *storage.KubeStorage, secrets v1.SecretInterface, refreshToken string) {
				refreshTokenSignature := getFositeDataSignature(t, refreshToken)
				firstRequester, err := oauthStore.GetRefreshTokenSession(context.Background(), refreshTokenSignature, nil)
				require.NoError(t, err)
				session := firstRequester.GetSession().(*psession.PinnipedSession)
				fositeSessionClaims := session.Fosite.IDTokenClaims()
				fositeSessionClaims.AuthTime = time.Time{}
				session.Fosite.Claims = fositeSessionClaims
				err = oauthStore.DeleteRefreshTokenSession(context.Background(), refreshTokenSignature)
				require.NoError(t, err)
				err = oauthStore.CreateRefreshTokenSession(context.Background(), refreshTokenSignature, "ignored", firstRequester)
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// First exchange the authcode for tokens, including a refresh token.
			// It's actually fine to use this function even when simulating LDAP (which uses a different flow) because it's
			// just populating a secret in storage.
			subject, rsp, authCode, jwtSigningKey, secrets, oauthStore, actualAuditLog, actualSessionID := exchangeAuthcodeForTokens(t,
				test.authcodeExchange, test.idps.BuildFederationDomainIdentityProvidersListerFinder(), test.kubeResources)
			var parsedAuthcodeExchangeResponseBody map[string]any
			require.NoError(t, json.Unmarshal(rsp.Body.Bytes(), &parsedAuthcodeExchangeResponseBody))

			// Performing an authcode exchange should not have caused any upstream refresh, which should only
			// happen during a downstream refresh.
			test.idps.RequireExactlyZeroCallsToAnyUpstreamRefresh(t)
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
				test.modifyRefreshTokenStorage(t, oauthStore, secrets, firstRefreshToken)
			}

			reqContextWarningRecorder := &TestWarningRecorder{}
			req := httptest.NewRequest("POST", "/path/shouldn't/matter",
				happyRefreshRequestBody(firstRefreshToken).ReadCloser()).
				WithContext(warning.WithWarningRecorder(
					context.WithValue(context.Background(), struct{ name string }{name: "test"}, "request-context"),
					reqContextWarningRecorder,
				))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req, _ = auditid.NewRequestWithAuditID(req, func() string { return "fake-refresh-grant-audit-id" })
			if test.refreshRequest.modifyTokenRequest != nil {
				test.refreshRequest.modifyTokenRequest(req, firstRefreshToken, parsedAuthcodeExchangeResponseBody["access_token"].(string))
			}

			actualAuditLog.Reset() // Clear audit logs from the authcode exchange
			refreshResponse := httptest.NewRecorder()
			approxRequestTime := time.Now()
			subject.ServeHTTP(refreshResponse, req)
			t.Logf("second response: %#v", refreshResponse)
			t.Logf("second response body: %q", refreshResponse.Body.String())

			// Test that we did or did not make a call to the upstream provider's interface to perform refresh.
			switch {
			case test.refreshRequest.want.wantOIDCUpstreamRefreshCall != nil:
				test.refreshRequest.want.wantOIDCUpstreamRefreshCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneCallToOIDCPerformRefresh(t,
					test.refreshRequest.want.wantOIDCUpstreamRefreshCall.performedByUpstreamName,
					test.refreshRequest.want.wantOIDCUpstreamRefreshCall.args,
				)
			case test.refreshRequest.want.wantLDAPUpstreamRefreshCall != nil:
				test.refreshRequest.want.wantLDAPUpstreamRefreshCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneCallToLDAPPerformRefresh(t,
					test.refreshRequest.want.wantLDAPUpstreamRefreshCall.performedByUpstreamName,
					test.refreshRequest.want.wantLDAPUpstreamRefreshCall.args,
				)
			case test.refreshRequest.want.wantActiveDirectoryUpstreamRefreshCall != nil:
				test.refreshRequest.want.wantActiveDirectoryUpstreamRefreshCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneCallToActiveDirectoryPerformRefresh(t,
					test.refreshRequest.want.wantActiveDirectoryUpstreamRefreshCall.performedByUpstreamName,
					test.refreshRequest.want.wantActiveDirectoryUpstreamRefreshCall.args,
				)
			case test.refreshRequest.want.wantGithubUpstreamRefreshCall != nil:
				test.refreshRequest.want.wantGithubUpstreamRefreshCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneCallToGithubGetUser(t,
					test.refreshRequest.want.wantGithubUpstreamRefreshCall.performedByUpstreamName,
					test.refreshRequest.want.wantGithubUpstreamRefreshCall.args,
				)
			default:
				test.idps.RequireExactlyZeroCallsToAnyUpstreamRefresh(t)
			}

			// Test that we did or did not make a call to the upstream OIDC provider interface to validate the
			// new ID token that was returned by the upstream refresh, in the case of an OIDC upstream.
			if test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall != nil {
				test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.args.Ctx = req.Context()
				test.idps.RequireExactlyOneCallToValidateToken(t,
					test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.performedByUpstreamName,
					test.refreshRequest.want.wantUpstreamOIDCValidateTokenCall.args,
				)
			} else {
				test.idps.RequireExactlyZeroCallsToValidateToken(t)
			}

			// Test that the expected warnings were set on the request context.
			if test.refreshRequest.want.wantWarnings != nil {
				require.Equal(t, test.refreshRequest.want.wantWarnings, reqContextWarningRecorder.Warnings)
			} else {
				require.Len(t, reqContextWarningRecorder.Warnings, 0, "wanted no warnings on the request context, but found some")
			}

			// Refreshed ID tokens do not include the nonce from the original auth request
			wantNonceValueInIDToken := false

			requireTokenEndpointBehavior(
				t,
				test.refreshRequest.want,
				wantNonceValueInIDToken,
				refreshResponse,
				authCode,
				oauthStore,
				jwtSigningKey,
				secrets,
				approxRequestTime,
				actualSessionID,
				"fake-refresh-grant-audit-id",
				actualAuditLog,
			)

			if test.refreshRequest.want.wantStatus == http.StatusOK {
				wantIDToken := slices.Contains(test.refreshRequest.want.wantSuccessBodyFields, "id_token")

				var parsedRefreshResponseBody map[string]any
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
					var claimsOfFirstIDToken map[string]any
					firstIDTokenDecoded, _ := josejwt.ParseSigned(parsedAuthcodeExchangeResponseBody["id_token"].(string), []jose.SignatureAlgorithm{jose.ES256})
					err := firstIDTokenDecoded.UnsafeClaimsWithoutVerification(&claimsOfFirstIDToken)
					require.NoError(t, err)

					var claimsOfSecondIDToken map[string]any
					secondIDTokenDecoded, _ := josejwt.ParseSigned(parsedRefreshResponseBody["id_token"].(string), []jose.SignatureAlgorithm{jose.ES256})
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

func requireClaimsAreNotEqual(t *testing.T, claimName string, claimsOfTokenA map[string]any, claimsOfTokenB map[string]any) {
	require.NotEmpty(t, claimsOfTokenA[claimName])
	require.NotEmpty(t, claimsOfTokenB[claimName])
	require.NotEqual(t, claimsOfTokenA[claimName], claimsOfTokenB[claimName])
}

func requireClaimsAreEqual(t *testing.T, claimName string, claimsOfTokenA map[string]any, claimsOfTokenB map[string]any) {
	require.NotEmpty(t, claimsOfTokenA[claimName])
	require.NotEmpty(t, claimsOfTokenB[claimName])
	require.Equal(t, claimsOfTokenA[claimName], claimsOfTokenB[claimName])
}

func exchangeAuthcodeForTokens(
	t *testing.T,
	test authcodeExchangeInputs,
	idps federationdomainproviders.FederationDomainIdentityProvidersListerFinderI,
	kubeResources func(t *testing.T, supervisorClient *supervisorfake.Clientset, kubeClient *fake.Clientset),
) (
	subject http.Handler,
	rsp *httptest.ResponseRecorder,
	authCode string,
	jwtSigningKey *ecdsa.PrivateKey,
	secrets v1.SecretInterface,
	oauthStore *storage.KubeStorage,
	actualAuditLog *bytes.Buffer,
	actualSessionID string,
) {
	authRequest := deepCopyRequestForm(happyAuthRequest)
	if test.modifyAuthRequest != nil {
		test.modifyAuthRequest(authRequest)
	}

	kubeClient := fake.NewSimpleClientset()
	supervisorClient := supervisorfake.NewSimpleClientset()
	secrets = kubeClient.CoreV1().Secrets("some-namespace")
	oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients("some-namespace")

	if kubeResources != nil {
		kubeResources(t, supervisorClient, kubeClient)
	}

	// Use the same timeouts configuration as the production code will use.
	timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()

	// Use lower minimum required bcrypt cost than we would use in production to keep unit the tests fast.
	oauthStore = storage.NewKubeStorage(secrets, oidcClientsClient, timeoutsConfiguration, bcrypt.MinCost)

	if test.makeJwksSigningKeyAndProvider == nil {
		test.makeJwksSigningKeyAndProvider = generateJWTSigningKeyAndJWKSProvider
	}

	auditLogger, actualAuditLog := plog.TestAuditLogger(t)

	var oauthHelper fosite.OAuth2Provider
	// Note that makeHappyOauthHelper() calls simulateAuthEndpointHavingAlreadyRun() to preload the session storage.
	oauthHelper, authCode, jwtSigningKey = makeHappyOauthHelper(t, authRequest, oauthStore, test.makeJwksSigningKeyAndProvider, test.customSessionData, test.modifySession)

	subject = NewHandler(
		idps,
		oauthHelper,
		timeoutsConfiguration.OverrideDefaultAccessTokenLifespan,
		timeoutsConfiguration.OverrideDefaultIDTokenLifespan,
		auditLogger,
	)

	authorizeEndpointGrantedOpenIDScope := strings.Contains(authRequest.Form.Get("scope"), "openid")
	expectedNumberOfIDSessionsStored := 0
	if authorizeEndpointGrantedOpenIDScope {
		expectedNumberOfIDSessionsStored = 1
	}

	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: pkce.TypeLabelValue}, 1)
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, expectedNumberOfIDSessionsStored)
	// Assert the number of all secrets, excluding any OIDCClient's storage secret, since those are not related to session storage.
	testutil.RequireNumberOfSecretsExcludingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: oidcclientsecretstorage.TypeLabelValue}, 2+expectedNumberOfIDSessionsStored)

	req := httptest.NewRequest("POST", "/path/shouldn't/matter", happyAuthcodeRequestBody(authCode).ReadCloser())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if test.modifyTokenRequest != nil {
		test.modifyTokenRequest(req, authCode)
	}
	req, _ = auditid.NewRequestWithAuditID(req, func() string { return "fake-code-grant-audit-id" })
	rsp = httptest.NewRecorder()

	approxRequestTime := time.Now()
	subject.ServeHTTP(rsp, req)
	t.Logf("response: %#v", rsp)
	t.Logf("response body: %q", rsp.Body.String())

	actualSessionID = getSessionID(t, secrets)

	wantNonceValueInIDToken := true // ID tokens returned by the authcode exchange must include the nonce from the auth request (unlike refreshed ID tokens)

	requireTokenEndpointBehavior(
		t,
		test.want,
		wantNonceValueInIDToken,
		rsp,
		authCode,
		oauthStore,
		jwtSigningKey,
		secrets,
		approxRequestTime,
		actualSessionID,
		"fake-code-grant-audit-id",
		actualAuditLog,
	)

	return subject, rsp, authCode, jwtSigningKey, secrets, oauthStore, actualAuditLog, actualSessionID
}

func getSessionID(t *testing.T, secrets v1.SecretInterface) string {
	t.Helper()

	authCodeLabelSelector := fmt.Sprintf("%s=%s", crud.SecretLabelKey, authorizationcode.TypeLabelValue)
	allAuthCodeSecrets, _ := secrets.List(context.Background(), metav1.ListOptions{
		LabelSelector: authCodeLabelSelector,
	})
	require.NotNil(t, allAuthCodeSecrets)
	require.Len(t, allAuthCodeSecrets.Items, 1, "expected exactly one secret with label %s", authCodeLabelSelector)
	session, err := authorizationcode.ReadFromSecret(&allAuthCodeSecrets.Items[0])
	require.NoError(t, err)
	return session.Request.GetID()
}

func requireTokenEndpointBehavior(
	t *testing.T,
	test tokenEndpointResponseExpectedValues,
	wantNonceValueInIDToken bool,
	tokenEndpointResponse *httptest.ResponseRecorder,
	authCode string,
	oauthStore *storage.KubeStorage,
	jwtSigningKey *ecdsa.PrivateKey,
	secrets v1.SecretInterface,
	requestTime time.Time,
	actualSessionID string,
	wantAuditID string,
	actualAuditLog *bytes.Buffer,
) {
	testutil.RequireEqualContentType(t, tokenEndpointResponse.Header().Get("Content-Type"), "application/json")
	require.Equal(t, test.wantStatus, tokenEndpointResponse.Code)

	var actualIDToken string
	if test.wantStatus == http.StatusOK {
		require.NotNil(t, test.wantSuccessBodyFields, "problem with test table setup: wanted success but did not specify expected response body")

		var parsedResponseBody map[string]any
		require.NoError(t, json.Unmarshal(tokenEndpointResponse.Body.Bytes(), &parsedResponseBody))
		require.ElementsMatch(t, test.wantSuccessBodyFields, getMapKeys(parsedResponseBody))

		wantIDToken := slices.Contains(test.wantSuccessBodyFields, "id_token")
		wantRefreshToken := slices.Contains(test.wantSuccessBodyFields, "refresh_token")

		requireInvalidAuthCodeStorage(t, authCode, oauthStore, secrets, requestTime)
		requireValidAccessTokenStorage(t, parsedResponseBody, oauthStore, test.wantClientID, test.wantRequestedScopes, test.wantGrantedScopes, test.wantUsername, test.wantGroups, test.wantCustomSessionDataStored, test.wantAdditionalClaims, secrets, requestTime)
		requireInvalidPKCEStorage(t, authCode, oauthStore)
		requireDeletedOIDCStorage(t, authCode, oauthStore) // The OIDC storage was deleted during the authcode exchange.

		expectedNumberOfRefreshTokenSessionsStored := 0
		if wantRefreshToken {
			expectedNumberOfRefreshTokenSessionsStored = 1
		}
		if wantIDToken {
			actualIDToken = requireValidIDToken(t, parsedResponseBody, jwtSigningKey, test.wantClientID, wantNonceValueInIDToken, test.wantUsername, test.wantGroups, test.wantAdditionalClaims, test.wantIDTokenLifetimeSeconds, parsedResponseBody["access_token"].(string), requestTime)
		}
		if wantRefreshToken {
			requireValidRefreshTokenStorage(t, parsedResponseBody, oauthStore, test.wantClientID, test.wantRequestedScopes, test.wantGrantedScopes, test.wantUsername, test.wantGroups, test.wantCustomSessionDataStored, test.wantAdditionalClaims, secrets, requestTime)
		}

		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: accesstoken.TypeLabelValue}, 1)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: pkce.TypeLabelValue}, 0)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: refreshtoken.TypeLabelValue}, expectedNumberOfRefreshTokenSessionsStored)
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 0)
		// Assert the number of all secrets, excluding any OIDCClient's storage secret, since those are not related to session storage.
		testutil.RequireNumberOfSecretsExcludingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: oidcclientsecretstorage.TypeLabelValue}, 2+expectedNumberOfRefreshTokenSessionsStored)
	} else {
		require.NotNil(t, test.wantErrorResponseBody, "problem with test table setup: wanted failure but did not specify failure response body")

		require.JSONEq(t, test.wantErrorResponseBody, tokenEndpointResponse.Body.String())
	}

	if test.wantAuditLogs != nil {
		wantAuditLogs := test.wantAuditLogs(actualSessionID, actualIDToken)
		testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, wantAuditID)
		testutil.CompareAuditLogs(t, wantAuditLogs, actualAuditLog.String())
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
		"client_id":     {pinnipedCLIClientID},
	}
}

func happyRefreshRequestBody(refreshToken string) body {
	return map[string][]string{
		"grant_type":    {"refresh_token"},
		"scope":         {"openid"},
		"client_id":     {pinnipedCLIClientID},
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

func (b body) WithClientSecret(clientSecret string) body {
	return b.with("client_secret", clientSecret)
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
	return io.NopCloser(strings.NewReader(url.Values(b).Encode()))
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

type MakeJwksSigningKeyAndProviderFunc func(t *testing.T, issuer string) (*ecdsa.PrivateKey, jwks.DynamicJWKSProvider)

func makeHappyOauthHelper(
	t *testing.T,
	authRequest *http.Request,
	store fositestoragei.AllFositeStorage,
	makeJwksSigningKeyAndProvider MakeJwksSigningKeyAndProviderFunc,
	initialCustomSessionData *psession.CustomSessionData,
	modifySession func(session *psession.PinnipedSession),
) (fosite.OAuth2Provider, string, *ecdsa.PrivateKey) {
	t.Helper()

	jwtSigningKey, jwkProvider := makeJwksSigningKeyAndProvider(t, goodIssuer)
	oauthHelper := oidc.FositeOauth2Helper(store, goodIssuer, hmacSecretFunc, jwkProvider, oidc.DefaultOIDCTimeoutsConfiguration())
	authResponder := simulateAuthEndpointHavingAlreadyRun(t, authRequest, oauthHelper, initialCustomSessionData, modifySession)
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

// Simulate the results of the auth endpoint (and possibly also the related callback or login endpoints) by getting
// fosite's code to fill the session store with realistic values. Regardless of the specific flow that the user uses to
// become authorized, all authorization flows conclude with the user's identity saved into a fosite session and an
// authorization code being issued to the client. So the goal of this function is to save the user's identity into a
// session in the same way that the production code for those other endpoints would have done it.
func simulateAuthEndpointHavingAlreadyRun(
	t *testing.T,
	authRequest *http.Request,
	oauthHelper fosite.OAuth2Provider,
	initialCustomSessionData *psession.CustomSessionData,
	modifySession func(session *psession.PinnipedSession),
) fosite.AuthorizeResponder {
	// We only set the fields in the session that Fosite wants us to set.
	ctx := context.Background()
	session := &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims: &fositejwt.IDTokenClaims{
				Subject:     goodSubject,
				RequestedAt: goodRequestedAtTime,
				AuthTime:    goodAuthTime,
				Extra:       map[string]any{},
			},
			Subject:  "", // not used, note that the authorization and callback endpoints do not set this
			Username: "", // not used, note that the authorization and callback endpoints do not set this
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

	// Set the downstream username and group names that normally would have been determined by the authorize and related
	// endpoints. These are stored into the fosite "extra" claims by the other endpoints, and when the token endpoint is
	// called later, it will be able to find this information inside the "extra" claims in the session.
	// The authorization endpoint makes a special exception for the pinniped-cli client for backwards compatibility
	// and grants the username and groups scopes to that client even if it did not ask for them. Simulate that
	// behavior here too by always adding these extras when the client_id is the Pinniped CLI client.
	// Note that these (and anything else in the session) can be overridden by the modifySession param.
	if strings.Contains(authRequest.Form.Get("scope"), "username") || authRequest.Form.Get("client_id") == pinnipedCLIClientID {
		authRequester.GrantScope("username")
		session.Fosite.Claims.Extra["username"] = goodUsername
	}
	if strings.Contains(authRequest.Form.Get("scope"), "groups") || authRequest.Form.Get("client_id") == pinnipedCLIClientID {
		authRequester.GrantScope("groups")
		session.Fosite.Claims.Extra["groups"] = goodGroups
	}

	// The authorization endpoint sets the authorized party to the client ID of the original requester.
	session.Fosite.Claims.Extra["azp"] = authRequester.GetClient().GetID()

	// Allow some tests to further modify the session before it is stored.
	if modifySession != nil {
		modifySession(session)
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
	requestTime time.Time,
) {
	t.Helper()

	// Make sure we have invalidated this auth code.
	_, err := storage.GetAuthorizeCodeSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.True(t, errors.Is(err, fosite.ErrInvalidatedAuthorizeCode))
	// make sure that its still around in storage so if someone tries to use it again we invalidate everything
	requireGarbageCollectTimeInDelta(t, code, "authcode", secrets, requestTime.Add(9*time.Hour).Add(10*time.Minute), 30*time.Second)
}

func requireValidRefreshTokenStorage(
	t *testing.T,
	body map[string]any,
	storage fositeoauth2.CoreStorage,
	wantClientID string,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantUsername string,
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
	wantAdditionalClaims map[string]any,
	secrets v1.SecretInterface,
	requestTime time.Time,
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
		wantClientID,
		wantRequestedScopes,
		wantGrantedScopes,
		true,
		wantUsername,
		wantGroups,
		wantCustomSessionData,
		wantAdditionalClaims,
		requestTime,
	)

	requireGarbageCollectTimeInDelta(t, refreshTokenString, "refresh-token", secrets, requestTime.Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireValidAccessTokenStorage(
	t *testing.T,
	body map[string]any,
	storage fositeoauth2.CoreStorage,
	wantClientID string,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantUsername string,
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
	wantAdditionalClaims map[string]any,
	secrets v1.SecretInterface,
	requestTime time.Time,
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
		wantClientID,
		wantRequestedScopes,
		wantGrantedScopes,
		true,
		wantUsername,
		wantGroups,
		wantCustomSessionData,
		wantAdditionalClaims,
		requestTime,
	)

	requireGarbageCollectTimeInDelta(t, accessTokenString, "access-token", secrets, requestTime.Add(9*time.Hour).Add(2*time.Minute), 1*time.Minute)
}

func requireInvalidAccessTokenStorage(
	t *testing.T,
	body map[string]any,
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
	storage fositepkce.PKCERequestStorage,
) {
	t.Helper()

	// Make sure the PKCE session has been deleted. Note that Fosite stores PKCE codes using the auth code signature
	// as a key.
	_, err := storage.GetPKCERequestSession(context.Background(), getFositeDataSignature(t, code), nil)
	require.True(t, errors.Is(err, fosite.ErrNotFound))
}

func requireDeletedOIDCStorage(t *testing.T, code string, storage openid.OpenIDConnectRequestStorage) {
	t.Helper()

	_, err := storage.GetOpenIDConnectSession(context.Background(), code, nil)
	require.True(t, errors.Is(err, fosite.ErrNotFound))
}

func requireValidStoredRequest(
	t *testing.T,
	request fosite.Requester,
	wantRequestForm url.Values,
	wantClientID string,
	wantRequestedScopes []string,
	wantGrantedScopes []string,
	wantAccessTokenExpiresAt bool,
	wantUsername string,
	wantGroups []string,
	wantCustomSessionData *psession.CustomSessionData,
	wantAdditionalClaims map[string]any,
	requestTime time.Time,
) {
	t.Helper()

	// Assert that the getters on the request return what we think they should.
	require.NotEmpty(t, request.GetID())
	testutil.RequireTimeInDelta(t, request.GetRequestedAt(), requestTime.UTC(), timeComparisonFudge)
	require.Equal(t, wantClientID, request.GetClient().GetID())
	require.Equal(t, fosite.Arguments(wantRequestedScopes), request.GetRequestedScopes())
	require.Equal(t, fosite.Arguments(wantGrantedScopes), request.GetGrantedScopes())
	require.Empty(t, request.GetRequestedAudience())
	require.Empty(t, request.GetGrantedAudience())
	require.Equal(t, wantRequestForm, request.GetRequestForm()) // Fosite stores access token request without form

	// Cast session to the type we think it should be.
	session, ok := request.GetSession().(*psession.PinnipedSession)
	require.Truef(t, ok, "could not cast %T to %T", request.GetSession(), &psession.PinnipedSession{})

	// Assert that the session claims are what we think they should be.
	claims := session.Fosite.Claims
	require.Empty(t, claims.JTI) // When claims.JTI is empty, Fosite will generate a UUID for this field.
	require.Equal(t, goodSubject, claims.Subject)

	// Our custom claims from the authorize endpoint should still be set.
	expectedExtra := map[string]any{}
	if wantUsername != "" {
		expectedExtra["username"] = wantUsername
	}
	if wantGroups != nil {
		expectedExtra["groups"] = toSliceOfInterface(wantGroups)
	}
	expectedExtra["azp"] = wantClientID
	if len(wantAdditionalClaims) > 0 {
		expectedExtra["additionalClaims"] = wantAdditionalClaims
	}
	require.Equal(t, expectedExtra, claims.Extra)

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

	// Assert that the session headers are what we think they should be.
	headers := session.Fosite.Headers
	require.Empty(t, headers)

	// Assert that the token expirations are what we think they should be.
	authCodeExpiresAt, ok := session.Fosite.ExpiresAt[fosite.AuthorizeCode]
	require.True(t, ok, "expected session to hold expiration time for auth code")
	testutil.RequireTimeInDelta(
		t,
		requestTime.UTC().Add(authCodeExpirationSeconds*time.Second),
		authCodeExpiresAt,
		timeComparisonFudge,
	)

	// OpenID Connect sessions do not store access token expiration information.
	accessTokenExpiresAt, ok := session.Fosite.ExpiresAt[fosite.AccessToken]
	if wantAccessTokenExpiresAt {
		require.True(t, ok, "expected session to hold expiration time for access token")
		testutil.RequireTimeInDelta(
			t,
			requestTime.UTC().Add(accessTokenExpirationSeconds*time.Second),
			accessTokenExpiresAt,
			timeComparisonFudge,
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
	body map[string]any,
	jwtSigningKey *ecdsa.PrivateKey,
	wantClientID string,
	wantNonceValueInIDToken bool,
	wantUsernameInIDToken string,
	wantGroupsInIDToken []string,
	wantAdditionalClaims map[string]any,
	wantIDTokenLifetimeSeconds int,
	actualAccessToken string,
	requestTime time.Time,
) string {
	t.Helper()

	idToken, ok := body["id_token"]
	require.Truef(t, ok, "body did not contain 'id_token': %s", body)
	idTokenString, ok := idToken.(string)
	require.Truef(t, ok, "wanted id_token to be a string, but got %T", idToken)

	// The go-oidc library will validate the signature and the client claim in the ID token.
	token := oidctestutil.VerifyECDSAIDToken(t, goodIssuer, wantClientID, jwtSigningKey, idTokenString)

	var claims struct {
		Subject          string         `json:"sub"`
		Audience         []string       `json:"aud"`
		Issuer           string         `json:"iss"`
		JTI              string         `json:"jti"`
		Nonce            string         `json:"nonce"`
		AccessTokenHash  string         `json:"at_hash"`
		ExpiresAt        int64          `json:"exp"`
		IssuedAt         int64          `json:"iat"`
		RequestedAt      int64          `json:"rat"`
		AuthTime         int64          `json:"auth_time"`
		Groups           []string       `json:"groups"`
		Username         string         `json:"username"`
		AdditionalClaims map[string]any `json:"additionalClaims"`
	}

	idTokenFields := []string{"sub", "aud", "iss", "jti", "auth_time", "exp", "iat", "rat", "azp", "at_hash"}
	if wantNonceValueInIDToken {
		idTokenFields = append(idTokenFields, "nonce")
	}
	if wantUsernameInIDToken != "" {
		idTokenFields = append(idTokenFields, "username")
	}
	if wantGroupsInIDToken != nil {
		idTokenFields = append(idTokenFields, "groups")
	}
	if len(wantAdditionalClaims) > 0 {
		idTokenFields = append(idTokenFields, "additionalClaims")
	}

	// make sure that these are the only fields in the token
	var m map[string]any
	require.NoError(t, token.Claims(&m))
	require.ElementsMatch(t, idTokenFields, getMapKeys(m))

	// verify each of the claims
	err := token.Claims(&claims)
	require.NoError(t, err)
	require.Equal(t, goodSubject, claims.Subject)
	require.Equal(t, wantUsernameInIDToken, claims.Username)
	require.Equal(t, wantGroupsInIDToken, claims.Groups)
	require.Len(t, claims.Audience, 1)
	require.Equal(t, wantClientID, claims.Audience[0])
	require.Equal(t, wantClientID, m["azp"])
	require.Equal(t, goodIssuer, claims.Issuer)
	require.NotEmpty(t, claims.JTI)
	require.Equal(t, wantAdditionalClaims, claims.AdditionalClaims)
	require.NotEqual(t, map[string]any{}, claims.AdditionalClaims, "additionalClaims may never be present and empty in the id token")

	if wantNonceValueInIDToken {
		require.Equal(t, goodNonce, claims.Nonce)
	} else {
		require.Empty(t, claims.Nonce)
	}

	if wantIDTokenLifetimeSeconds == 0 {
		// When not specified, assert that the ID token has the default lifetime for an ID token.
		wantIDTokenLifetimeSeconds = idTokenExpirationSeconds
	}

	// The difference between iat (issued at) and exp (expires at) claims should be exactly the lifetime seconds.
	require.Equal(t, int64(wantIDTokenLifetimeSeconds), claims.ExpiresAt-claims.IssuedAt, "ID token lifetime was not the expected value")

	expiresAt := time.Unix(claims.ExpiresAt, 0)
	issuedAt := time.Unix(claims.IssuedAt, 0)
	requestedAt := time.Unix(claims.RequestedAt, 0)
	authTime := time.Unix(claims.AuthTime, 0)
	testutil.RequireTimeInDelta(t, requestTime.UTC().Add(time.Duration(wantIDTokenLifetimeSeconds)*time.Second), expiresAt, timeComparisonFudge)
	testutil.RequireTimeInDelta(t, requestTime.UTC(), issuedAt, timeComparisonFudge)
	testutil.RequireTimeInDelta(t, goodRequestedAtTime, requestedAt, timeComparisonFudge)
	testutil.RequireTimeInDelta(t, goodAuthTime, authTime, timeComparisonFudge)

	require.NotEmpty(t, actualAccessToken)
	require.Equal(t, hashAccessToken(actualAccessToken), claims.AccessTokenHash)

	return idTokenString
}

func deepCopyRequestForm(r *http.Request) *http.Request {
	copied := url.Values{}
	for k, v := range r.Form {
		copied[k] = v
	}
	return &http.Request{Form: copied}
}

func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0)
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func toSliceOfInterface(s []string) []any {
	r := make([]any, len(s))
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
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			added, removed := diffSortedGroups(test.oldGroups, test.newGroups)
			require.Equal(t, test.wantAdded, added)
			require.Equal(t, test.wantRemoved, removed)
		})
	}
}

type RecordedWarning struct {
	Agent string
	Text  string
}

type TestWarningRecorder struct {
	Warnings []RecordedWarning
}

var _ warning.Recorder = (*TestWarningRecorder)(nil)

func (t *TestWarningRecorder) AddWarning(agent, text string) {
	if t.Warnings == nil {
		t.Warnings = []RecordedWarning{}
	}
	t.Warnings = append(t.Warnings, RecordedWarning{
		Agent: agent,
		Text:  text,
	})
}

func getSecretNameFromSignature(t *testing.T, signature string, typeLabel string) string {
	t.Helper()
	// try to decode base64 signatures to prevent double encoding of binary data
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	require.NoError(t, err)
	// lower case base32 encoding insures that our secret name is valid per ValidateSecretName in k/k
	var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	signatureAsValidName := strings.ToLower(b32.EncodeToString(signatureBytes))
	return fmt.Sprintf("pinniped-storage-%s-%s", typeLabel, signatureAsValidName)
}

// TestParamsSafeToLog only exists to ensure that paramsSafeToLog will not be accidentally updated.
func TestParamsSafeToLog(t *testing.T) {
	wantParams := []string{
		"actor_token_type",
		"audience",
		"client_id",
		"grant_type",
		"redirect_uri",
		"requested_token_type",
		"resource",
		"scope",
		"subject_token_type",
	}

	require.ElementsMatch(t, wantParams, paramsSafeToLog().UnsortedList())
}

func TestIntToKB(t *testing.T) {
	tests := []struct {
		name string
		i    int
		want string
	}{
		{
			name: "happy path <2^10",
			i:    500,
			want: "500 Bytes",
		},
		{
			name: "happy path >2^10, will round",
			i:    1175, // 1175 / 1024 = 1.14746094
			want: "1.15 KiB",
		},
		{
			name: "happy path >2^20, will round",
			i:    12345678, // 12345678 / 1024 = 12,056.32617188
			want: "12056.33 KiB",
		},
		{
			name: "negative number prints negative",
			i:    -1234,
			want: "-1234 Bytes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := intToKB(test.i)
			require.Equal(t, test.want, actual)
		})
	}
}
