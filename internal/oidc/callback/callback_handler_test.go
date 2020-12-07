// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/oidctestutil"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	oidcpkce "go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	happyUpstreamIDPName = "upstream-idp-name"

	upstreamIssuer   = "https://my-upstream-issuer.com"
	upstreamSubject  = "abc123-some-guid"
	upstreamUsername = "test-pinniped-username"

	upstreamUsernameClaim = "the-user-claim"
	upstreamGroupsClaim   = "the-groups-claim"

	happyUpstreamAuthcode = "upstream-auth-code"

	happyUpstreamRedirectURI = "https://example.com/callback"

	happyDownstreamState        = "some-downstream-state-with-at-least-32-bytes"
	happyDownstreamCSRF         = "test-csrf"
	happyDownstreamPKCE         = "test-pkce"
	happyDownstreamNonce        = "test-nonce"
	happyDownstreamStateVersion = "1"

	downstreamIssuer              = "https://my-downstream-issuer.com/path"
	downstreamRedirectURI         = "http://127.0.0.1/callback"
	downstreamClientID            = "pinniped-cli"
	downstreamNonce               = "some-nonce-value"
	downstreamPKCEChallenge       = "some-challenge"
	downstreamPKCEChallengeMethod = "S256"

	timeComparisonFudgeFactor = time.Second * 15
)

var (
	upstreamGroupMembership        = []string{"test-pinniped-group-0", "test-pinniped-group-1"}
	happyDownstreamScopesRequested = []string{"openid", "profile", "email"}

	happyDownstreamRequestParamsQuery = url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{strings.Join(happyDownstreamScopesRequested, " ")},
		"client_id":             []string{downstreamClientID},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{downstreamNonce},
		"code_challenge":        []string{downstreamPKCEChallenge},
		"code_challenge_method": []string{downstreamPKCEChallengeMethod},
		"redirect_uri":          []string{downstreamRedirectURI},
	}
	happyDownstreamRequestParams = happyDownstreamRequestParamsQuery.Encode()
)

func TestCallbackEndpoint(t *testing.T) {
	otherUpstreamOIDCIdentityProvider := oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:     "other-upstream-idp-name",
		ClientID: "other-some-client-id",
		Scopes:   []string{"other-scope1", "other-scope2"},
	}

	var stateEncoderHashKey = []byte("fake-hash-secret")
	var stateEncoderBlockKey = []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	var cookieEncoderHashKey = []byte("fake-hash-secret2")
	var cookieEncoderBlockKey = []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	var happyStateCodec = securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateCodec.SetSerializer(securecookie.JSONEncoder{})
	var happyCookieCodec = securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieCodec.SetSerializer(securecookie.JSONEncoder{})

	happyState := happyUpstreamStateParam().Build(t, happyStateCodec)

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	happyExchangeAndValidateTokensArgs := &oidctestutil.ExchangeAuthcodeAndValidateTokenArgs{
		Authcode:             happyUpstreamAuthcode,
		PKCECodeVerifier:     oidcpkce.Code(happyDownstreamPKCE),
		ExpectedIDTokenNonce: nonce.Nonce(happyDownstreamNonce),
		RedirectURI:          happyUpstreamRedirectURI,
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid&state=` + happyDownstreamState

	tests := []struct {
		name string

		idp        oidctestutil.TestUpstreamOIDCIdentityProvider
		method     string
		path       string
		csrfCookie string

		wantStatus                        int
		wantBody                          string
		wantRedirectLocationRegexp        string
		wantGrantedOpenidScope            bool
		wantDownstreamIDTokenSubject      string
		wantDownstreamIDTokenGroups       []string
		wantDownstreamRequestedScopes     []string
		wantDownstreamNonce               string
		wantDownstreamPKCEChallenge       string
		wantDownstreamPKCEChallengeMethod string

		wantExchangeAndValidateTokensCall *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs
	}{
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 302 to downstream client callback with its state and code",
			idp:                               happyUpstream().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantGrantedOpenidScope:            true,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamUsername,
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idp:                               happyUpstream().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantGrantedOpenidScope:            true,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + upstreamSubject,
			wantDownstreamIDTokenGroups:       nil,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idp:                               happyUpstream().WithUsernameClaim("sub").Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantGrantedOpenidScope:            true,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamSubject,
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},

		// Pre-upstream-exchange verification
		{
			name:       "PUT method is invalid",
			method:     http.MethodPut,
			path:       newRequestPath().String(),
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed: PUT (try GET)\n",
		},
		{
			name:       "POST method is invalid",
			method:     http.MethodPost,
			path:       newRequestPath().String(),
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed: POST (try GET)\n",
		},
		{
			name:       "PATCH method is invalid",
			method:     http.MethodPatch,
			path:       newRequestPath().String(),
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed: PATCH (try GET)\n",
		},
		{
			name:       "DELETE method is invalid",
			method:     http.MethodDelete,
			path:       newRequestPath().String(),
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed: DELETE (try GET)\n",
		},
		{
			name:       "code param was not included on request",
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyState).WithoutCode().String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Bad Request: code param not found\n",
		},
		{
			name:       "state param was not included on request",
			method:     http.MethodGet,
			path:       newRequestPath().WithoutState().String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Bad Request: state param not found\n",
		},
		{
			name:       "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idp:        happyUpstream().Build(),
			method:     http.MethodGet,
			path:       newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Bad Request: error reading state\n",
		},
		{
			// This shouldn't happen in practice because the authorize endpoint should have already run the same
			// validations, but we would like to test the error handling in this endpoint anyway.
			name:   "state param contains authorization request params which fail validation",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"prompt": "none login"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
			wantStatus:                        http.StatusInternalServerError,
			wantBody:                          "Internal Server Error: error while generating and saving authcode\n",
		},
		{
			name:       "state's internal version does not match what we want",
			idp:        happyUpstream().Build(),
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyUpstreamStateParam().WithStateVersion("wrong-state-version").Build(t, happyStateCodec)).String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "Unprocessable Entity: state format version is invalid\n",
		},
		{
			name:   "state's downstream auth params element is invalid",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(happyUpstreamStateParam().
				WithAuthorizeRequestParams("the following is an invalid url encoding token, and therefore this is an invalid param: %z").
				Build(t, happyStateCodec)).String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Bad Request: error reading state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params are missing required value (e.g., client_id)",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"client_id": ""}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusBadRequest,
			wantBody:   "Bad Request: error using state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params does not contain openid scope",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"scope": "profile email"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=&state=` + happyDownstreamState,
			wantDownstreamIDTokenSubject:      upstreamUsername,
			wantDownstreamRequestedScopes:     []string{"profile", "email"},
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:       "the UpstreamOIDCProvider CRD has been deleted",
			idp:        otherUpstreamOIDCIdentityProvider,
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyState).String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "Unprocessable Entity: upstream provider not found\n",
		},
		{
			name:       "the CSRF cookie does not exist on request",
			idp:        happyUpstream().Build(),
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyState).String(),
			wantStatus: http.StatusForbidden,
			wantBody:   "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:       "cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idp:        happyUpstream().Build(),
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyState).String(),
			csrfCookie: "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus: http.StatusForbidden,
			wantBody:   "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:       "cookie csrf value does not match state csrf value",
			idp:        happyUpstream().Build(),
			method:     http.MethodGet,
			path:       newRequestPath().WithState(happyUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie: happyCSRFCookie,
			wantStatus: http.StatusForbidden,
			wantBody:   "Forbidden: CSRF value does not match\n",
		},

		// Upstream exchange
		{
			name:                              "upstream auth code exchange fails",
			idp:                               happyUpstream().WithoutUpstreamAuthcodeExchangeError(errors.New("some error")).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusBadGateway,
			wantBody:                          "Bad Gateway: error exchanging and validating upstream tokens\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain requested username claim",
			idp:                               happyUpstream().WithoutIDTokenClaim(upstreamUsernameClaim).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: no username claim in upstream ID token\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain requested groups claim",
			idp:                               happyUpstream().WithoutIDTokenClaim(upstreamGroupsClaim).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: no groups claim in upstream ID token\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains username claim with weird format",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamUsernameClaim, 42).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: username claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain iss claim when using default username claim config",
			idp:                               happyUpstream().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: issuer claim in upstream ID token missing\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token has an non-string iss claim when using default username claim config",
			idp:                               happyUpstream().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: issuer claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains groups claim with weird format",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, 42).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: groups claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			secrets := client.CoreV1().Secrets("some-namespace")

			// Configure fosite the same way that the production code would.
			// Inject this into our test subject at the last second so we get a fresh storage for every test.
			oauthStore := oidc.NewKubeStorage(secrets)
			hmacSecret := []byte("some secret - must have at least 32 bytes")
			require.GreaterOrEqual(t, len(hmacSecret), 32, "fosite requires that hmac secrets have at least 32 bytes")
			jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
			oauthHelper := oidc.FositeOauth2Helper(oauthStore, downstreamIssuer, hmacSecret, jwksProviderIsUnused)

			idpListGetter := oidctestutil.NewIDPListGetter(&test.idp)
			subject := NewHandler(idpListGetter, oauthHelper, happyStateCodec, happyCookieCodec, happyUpstreamRedirectURI)
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			if test.wantExchangeAndValidateTokensCall != nil {
				require.Equal(t, 1, test.idp.ExchangeAuthcodeAndValidateTokensCallCount())
				test.wantExchangeAndValidateTokensCall.Ctx = req.Context()
				require.Equal(t, test.wantExchangeAndValidateTokensCall, test.idp.ExchangeAuthcodeAndValidateTokensArgs(0))
			} else {
				require.Equal(t, 0, test.idp.ExchangeAuthcodeAndValidateTokensCallCount())
			}

			require.Equal(t, test.wantStatus, rsp.Code)

			if test.wantBody != "" {
				require.Equal(t, test.wantBody, rsp.Body.String())
			} else {
				require.Empty(t, rsp.Body.String())
			}

			if test.wantRedirectLocationRegexp != "" { //nolint:nestif // don't mind have several sequential if statements in this test
				// Assert that Location header matches regular expression.
				require.Len(t, rsp.Header().Values("Location"), 1)
				actualLocation := rsp.Header().Get("Location")
				regex := regexp.MustCompile(test.wantRedirectLocationRegexp)
				submatches := regex.FindStringSubmatch(actualLocation)
				require.Lenf(t, submatches, 2, "no regexp match in actualLocation: %q", actualLocation)
				capturedAuthCode := submatches[1]

				// fosite authcodes are in the format `data.signature`, so grab the signature part, which is the lookup key in the storage interface
				authcodeDataAndSignature := strings.Split(capturedAuthCode, ".")
				require.Len(t, authcodeDataAndSignature, 2)

				// Several Secrets should have been created
				expectedNumberOfCreatedSecrets := 2
				if test.wantGrantedOpenidScope {
					expectedNumberOfCreatedSecrets++
				}
				require.Len(t, client.Actions(), expectedNumberOfCreatedSecrets)

				// One authcode should have been stored.
				testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)

				storedRequestFromAuthcode, storedSessionFromAuthcode := validateAuthcodeStorage(
					t,
					oauthStore,
					authcodeDataAndSignature[1], // Authcode store key is authcode signature
					test.wantGrantedOpenidScope,
					test.wantDownstreamIDTokenSubject,
					test.wantDownstreamIDTokenGroups,
					test.wantDownstreamRequestedScopes,
				)

				// One PKCE should have been stored.
				testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: pkce.TypeLabelValue}, 1)

				validatePKCEStorage(
					t,
					oauthStore,
					authcodeDataAndSignature[1], // PKCE store key is authcode signature
					storedRequestFromAuthcode,
					storedSessionFromAuthcode,
					test.wantDownstreamPKCEChallenge,
					test.wantDownstreamPKCEChallengeMethod,
				)

				// One IDSession should have been stored, if the downstream actually requested the "openid" scope
				if test.wantGrantedOpenidScope {
					testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secrets, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 1)

					validateIDSessionStorage(
						t,
						oauthStore,
						capturedAuthCode, // IDSession store key is full authcode
						storedRequestFromAuthcode,
						storedSessionFromAuthcode,
						test.wantDownstreamNonce,
					)
				}
			}
		})
	}
}

type requestPath struct {
	code, state *string
}

func newRequestPath() *requestPath {
	c := happyUpstreamAuthcode
	s := "4321"
	return &requestPath{
		code:  &c,
		state: &s,
	}
}

func (r *requestPath) WithCode(code string) *requestPath {
	r.code = &code
	return r
}

func (r *requestPath) WithoutCode() *requestPath {
	r.code = nil
	return r
}

func (r *requestPath) WithState(state string) *requestPath {
	r.state = &state
	return r
}

func (r *requestPath) WithoutState() *requestPath {
	r.state = nil
	return r
}

func (r *requestPath) String() string {
	path := "/downstream-provider-name/callback?"
	params := url.Values{}
	if r.code != nil {
		params.Add("code", *r.code)
	}
	if r.state != nil {
		params.Add("state", *r.state)
	}
	return path + params.Encode()
}

type upstreamStateParamBuilder oidctestutil.ExpectedUpstreamStateParamFormat

func happyUpstreamStateParam() *upstreamStateParamBuilder {
	return &upstreamStateParamBuilder{
		U: happyUpstreamIDPName,
		P: happyDownstreamRequestParams,
		N: happyDownstreamNonce,
		C: happyDownstreamCSRF,
		K: happyDownstreamPKCE,
		V: happyDownstreamStateVersion,
	}
}

func (b upstreamStateParamBuilder) Build(t *testing.T, stateEncoder *securecookie.SecureCookie) string {
	state, err := stateEncoder.Encode("s", b)
	require.NoError(t, err)
	return state
}

func (b *upstreamStateParamBuilder) WithAuthorizeRequestParams(params string) *upstreamStateParamBuilder {
	b.P = params
	return b
}

func (b *upstreamStateParamBuilder) WithNonce(nonce string) *upstreamStateParamBuilder {
	b.N = nonce
	return b
}

func (b *upstreamStateParamBuilder) WithCSRF(csrf string) *upstreamStateParamBuilder {
	b.C = csrf
	return b
}

func (b *upstreamStateParamBuilder) WithPKCVE(pkce string) *upstreamStateParamBuilder {
	b.K = pkce
	return b
}

func (b *upstreamStateParamBuilder) WithStateVersion(version string) *upstreamStateParamBuilder {
	b.V = version
	return b
}

type upstreamOIDCIdentityProviderBuilder struct {
	idToken                    map[string]interface{}
	usernameClaim, groupsClaim string
	authcodeExchangeErr        error
}

func happyUpstream() *upstreamOIDCIdentityProviderBuilder {
	return &upstreamOIDCIdentityProviderBuilder{
		usernameClaim: upstreamUsernameClaim,
		groupsClaim:   upstreamGroupsClaim,
		idToken: map[string]interface{}{
			"iss":                 upstreamIssuer,
			"sub":                 upstreamSubject,
			upstreamUsernameClaim: upstreamUsername,
			upstreamGroupsClaim:   upstreamGroupMembership,
			"other-claim":         "should be ignored",
		},
	}
}

func (u *upstreamOIDCIdentityProviderBuilder) WithUsernameClaim(claim string) *upstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = claim
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutUsernameClaim() *upstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = ""
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutGroupsClaim() *upstreamOIDCIdentityProviderBuilder {
	u.groupsClaim = ""
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithIDTokenClaim(name string, value interface{}) *upstreamOIDCIdentityProviderBuilder {
	u.idToken[name] = value
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutIDTokenClaim(claim string) *upstreamOIDCIdentityProviderBuilder {
	delete(u.idToken, claim)
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutUpstreamAuthcodeExchangeError(err error) *upstreamOIDCIdentityProviderBuilder {
	u.authcodeExchangeErr = err
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) Build() oidctestutil.TestUpstreamOIDCIdentityProvider {
	return oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:          happyUpstreamIDPName,
		ClientID:      "some-client-id",
		UsernameClaim: u.usernameClaim,
		GroupsClaim:   u.groupsClaim,
		Scopes:        []string{"scope1", "scope2"},
		ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier oidcpkce.Code, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
			if u.authcodeExchangeErr != nil {
				return nil, u.authcodeExchangeErr
			}
			return &oidctypes.Token{IDToken: &oidctypes.IDToken{Claims: u.idToken}}, nil
		},
	}
}

func shallowCopyAndModifyQuery(query url.Values, modifications map[string]string) url.Values {
	copied := url.Values{}
	for key, value := range query {
		copied[key] = value
	}
	for key, value := range modifications {
		if value == "" {
			copied.Del(key)
		} else {
			copied[key] = []string{value}
		}
	}
	return copied
}

func validateAuthcodeStorage(
	t *testing.T,
	oauthStore *oidc.KubeStorage,
	storeKey string,
	wantGrantedOpenidScope bool,
	wantDownstreamIDTokenSubject string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamRequestedScopes []string,
) (*fosite.Request, *openid.DefaultSession) {
	t.Helper()

	// Get the authcode session back from storage so we can require that it was stored correctly.
	storedAuthorizeRequestFromAuthcode, err := oauthStore.GetAuthorizeCodeSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromAuthcode, storedSessionFromAuthcode := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromAuthcode)

	// Check which scopes were granted.
	if wantGrantedOpenidScope {
		require.Contains(t, storedRequestFromAuthcode.GetGrantedScopes(), "openid")
	} else {
		require.NotContains(t, storedRequestFromAuthcode.GetGrantedScopes(), "openid")
	}

	// Check all the other fields of the stored request.
	require.NotEmpty(t, storedRequestFromAuthcode.ID)
	require.Equal(t, downstreamClientID, storedRequestFromAuthcode.Client.GetID())
	require.ElementsMatch(t, wantDownstreamRequestedScopes, storedRequestFromAuthcode.RequestedScope)
	require.Nil(t, storedRequestFromAuthcode.RequestedAudience)
	require.Empty(t, storedRequestFromAuthcode.GrantedAudience)
	require.Equal(t, url.Values{"redirect_uri": []string{downstreamRedirectURI}}, storedRequestFromAuthcode.Form)
	testutil.RequireTimeInDelta(t, time.Now(), storedRequestFromAuthcode.RequestedAt, timeComparisonFudgeFactor)

	// We're not using these fields yet, so confirm that we did not set them (for now).
	require.Empty(t, storedSessionFromAuthcode.Subject)
	require.Empty(t, storedSessionFromAuthcode.Username)
	require.Empty(t, storedSessionFromAuthcode.Headers)

	// The authcode that we are issuing should be good for the length of time that we declare in the fosite config.
	testutil.RequireTimeInDelta(t, time.Now().Add(time.Minute*3), storedSessionFromAuthcode.ExpiresAt[fosite.AuthorizeCode], timeComparisonFudgeFactor)
	require.Len(t, storedSessionFromAuthcode.ExpiresAt, 1)

	// Now confirm the ID token claims.
	actualClaims := storedSessionFromAuthcode.Claims

	// Check the user's identity, which are put into the downstream ID token's subject and groups claims.
	require.Equal(t, wantDownstreamIDTokenSubject, actualClaims.Subject)
	if wantDownstreamIDTokenGroups != nil {
		require.Len(t, actualClaims.Extra, 1)
		require.ElementsMatch(t, wantDownstreamIDTokenGroups, actualClaims.Extra["groups"])
	} else {
		require.Empty(t, actualClaims.Extra)
		require.NotContains(t, actualClaims.Extra, "groups")
	}

	// Check the rest of the downstream ID token's claims. Fosite wants us to set these (in UTC time).
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.RequestedAt, timeComparisonFudgeFactor)
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.AuthTime, timeComparisonFudgeFactor)
	requestedAtZone, _ := actualClaims.RequestedAt.Zone()
	require.Equal(t, "UTC", requestedAtZone)
	authTimeZone, _ := actualClaims.AuthTime.Zone()
	require.Equal(t, "UTC", authTimeZone)

	// Fosite will set these fields for us in the token endpoint based on the store session
	// information. Therefore, we assert that they are empty because we want the library to do the
	// lifting for us.
	require.Empty(t, actualClaims.Issuer)
	require.Nil(t, actualClaims.Audience)
	require.Empty(t, actualClaims.Nonce)
	require.Zero(t, actualClaims.ExpiresAt)
	require.Zero(t, actualClaims.IssuedAt)

	// These are not needed yet.
	require.Empty(t, actualClaims.JTI)
	require.Empty(t, actualClaims.CodeHash)
	require.Empty(t, actualClaims.AccessTokenHash)
	require.Empty(t, actualClaims.AuthenticationContextClassReference)
	require.Empty(t, actualClaims.AuthenticationMethodsReference)

	return storedRequestFromAuthcode, storedSessionFromAuthcode
}

func validatePKCEStorage(
	t *testing.T,
	oauthStore *oidc.KubeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *openid.DefaultSession,
	wantDownstreamPKCEChallenge, wantDownstreamPKCEChallengeMethod string,
) {
	t.Helper()

	storedAuthorizeRequestFromPKCE, err := oauthStore.GetPKCERequestSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromPKCE, storedSessionFromPKCE := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromPKCE)

	// The stored PKCE request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromPKCE.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromPKCE)

	// The stored PKCE request should also contain the PKCE challenge that the downstream sent us.
	require.Equal(t, wantDownstreamPKCEChallenge, storedRequestFromPKCE.Form.Get("code_challenge"))
	require.Equal(t, wantDownstreamPKCEChallengeMethod, storedRequestFromPKCE.Form.Get("code_challenge_method"))
}

func validateIDSessionStorage(
	t *testing.T,
	oauthStore *oidc.KubeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *openid.DefaultSession,
	wantDownstreamNonce string,
) {
	t.Helper()

	storedAuthorizeRequestFromIDSession, err := oauthStore.GetOpenIDConnectSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromIDSession, storedSessionFromIDSession := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromIDSession)

	// The stored IDSession request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromIDSession.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromIDSession)

	// The stored IDSession request should also contain the nonce that the downstream sent us.
	require.Equal(t, wantDownstreamNonce, storedRequestFromIDSession.Form.Get("nonce"))
}

func castStoredAuthorizeRequest(t *testing.T, storedAuthorizeRequest fosite.Requester) (*fosite.Request, *openid.DefaultSession) {
	t.Helper()

	storedRequest, ok := storedAuthorizeRequest.(*fosite.Request)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest, &fosite.Request{})
	storedSession, ok := storedAuthorizeRequest.GetSession().(*openid.DefaultSession)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest.GetSession(), &openid.DefaultSession{})

	return storedRequest, storedSession
}
