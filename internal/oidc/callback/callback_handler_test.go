// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/testutil"
)

const (
	happyUpstreamIDPName = "upstream-idp-name"
)

func TestCallbackEndpoint(t *testing.T) {
	const (
		downstreamRedirectURI = "http://127.0.0.1/callback"
	)

	// Configure fosite the same way that the production code would, except use in-memory storage.
	oauthStore := &storage.MemoryStore{
		Clients:        map[string]fosite.Client{oidc.PinnipedCLIOIDCClient().ID: oidc.PinnipedCLIOIDCClient()},
		AuthorizeCodes: map[string]storage.StoreAuthorizeCode{},
		PKCES:          map[string]fosite.Requester{},
		IDSessions:     map[string]fosite.Requester{},
	}
	hmacSecret := []byte("some secret - must have at least 32 bytes")
	require.GreaterOrEqual(t, len(hmacSecret), 32, "fosite requires that hmac secrets have at least 32 bytes")
	oauthHelper := oidc.FositeOauth2Helper(oauthStore, hmacSecret)

	upstreamOIDCIdentityProvider := testutil.TestUpstreamOIDCIdentityProvider{
		Name:          happyUpstreamIDPName,
		ClientID:      "some-client-id",
		UsernameClaim: "the-user-claim",
		GroupsClaim:   "the-groups-claim",
		Scopes:        []string{"scope1", "scope2"},
		ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce) (oidcclient.Token, map[string]interface{}, error) {
			return oidcclient.Token{},
				map[string]interface{}{
					"the-user-claim": "test-pinniped-username",
					"other-claim":    "should be ignored",
				},
				nil
		},
	}

	otherUpstreamOIDCIdentityProvider := testutil.TestUpstreamOIDCIdentityProvider{
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

	happyDownstreamState := "some-downstream-state"

	happyOriginalRequestParams := url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{"openid profile email"},
		"client_id":             []string{"pinniped-cli"},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{"some-nonce-value"},
		"code_challenge":        []string{"some-challenge"},
		"code_challenge_method": []string{"S256"},
		"redirect_uri":          []string{downstreamRedirectURI},
	}.Encode()
	happyCSRF := "test-csrf"
	happyPKCE := "test-pkce"
	happyNonce := "test-nonce"

	happyState, err := happyStateCodec.Encode("s",
		testutil.ExpectedUpstreamStateParamFormat{
			P: happyOriginalRequestParams,
			N: happyNonce,
			C: happyCSRF,
			K: happyPKCE,
			V: "1",
		},
	)
	require.NoError(t, err)

	wrongCSRFValueState, err := happyStateCodec.Encode("s",
		testutil.ExpectedUpstreamStateParamFormat{
			P: happyOriginalRequestParams,
			N: happyNonce,
			C: "wrong-csrf-value",
			K: happyPKCE,
			V: "1",
		},
	)
	require.NoError(t, err)

	wrongVersionState, err := happyStateCodec.Encode("s",
		testutil.ExpectedUpstreamStateParamFormat{
			P: happyOriginalRequestParams,
			N: happyNonce,
			C: happyCSRF,
			K: happyPKCE,
			V: "wrong-version",
		},
	)
	require.NoError(t, err)

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	tests := []struct {
		name string

		idpListGetter provider.DynamicUpstreamIDPProvider
		method        string
		path          string
		csrfCookie    string

		wantStatus                 int
		wantBody                   string
		wantRedirectLocationRegexp string
		wantAuthcodeStored         bool
	}{
		{
			name:          "GET with good state and cookie and successful upstream token exchange returns 302 to downstream client callback with its state and code",
			idpListGetter: testutil.NewIDPListGetter(upstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(happyState).String(),
			csrfCookie:    happyCSRFCookie,
			wantStatus:    http.StatusFound,
			// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
			wantRedirectLocationRegexp: downstreamRedirectURI + `\?code=([^&]+)&scope=openid&state=` + happyDownstreamState,
			wantAuthcodeStored:         true,
			wantBody:                   "",
		},
		// TODO: when we call the callback twice in a row, we get two different auth codes (to prove we are using an RNG for auth codes)

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
			name:          "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idpListGetter: testutil.NewIDPListGetter(upstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie:    happyCSRFCookie,
			wantStatus:    http.StatusBadRequest,
			wantBody:      "Bad Request: error reading state\n",
		},
		{
			name:          "state's internal version does not match what we want",
			idpListGetter: testutil.NewIDPListGetter(upstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(wrongVersionState).String(),
			csrfCookie:    happyCSRFCookie,
			wantStatus:    http.StatusUnprocessableEntity,
			wantBody:      "Unprocessable Entity: state format version is invalid\n",
		},
		{
			name:          "the UpstreamOIDCProvider CRD has been deleted",
			idpListGetter: testutil.NewIDPListGetter(otherUpstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(happyState).String(),
			csrfCookie:    happyCSRFCookie,
			wantStatus:    http.StatusUnprocessableEntity,
			wantBody:      "Unprocessable Entity: upstream provider not found\n",
		},
		{
			name:          "the CSRF cookie does not exist on request",
			idpListGetter: testutil.NewIDPListGetter(otherUpstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(happyState).String(),
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:          "cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idpListGetter: testutil.NewIDPListGetter(otherUpstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(happyState).String(),
			csrfCookie:    "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:          "cookie csrf value does not match state csrf value",
			idpListGetter: testutil.NewIDPListGetter(otherUpstreamOIDCIdentityProvider),
			method:        http.MethodGet,
			path:          newRequestPath().WithState(wrongCSRFValueState).String(),
			csrfCookie:    happyCSRFCookie,
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden: CSRF value does not match\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			subject := NewHandler(test.idpListGetter, oauthHelper, happyStateCodec, happyCookieCodec)
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)

			require.False(t, test.wantBody != "" && test.wantRedirectLocationRegexp != "", "test cannot set both body and redirect assertions")

			if test.wantBody != "" {
				require.Equal(t, test.wantBody, rsp.Body.String())
			} else {
				require.Empty(t, rsp.Body.String())
			}

			if test.wantRedirectLocationRegexp != "" {
				// Assert that Location header matches regular expression.
				require.Len(t, rsp.Header().Values("Location"), 1)
				actualLocation := rsp.Header().Get("Location")
				regex := regexp.MustCompile(test.wantRedirectLocationRegexp)
				submatches := regex.FindStringSubmatch(actualLocation)
				require.Lenf(t, submatches, 2, "no regexp match in actualLocation: %q", actualLocation)
				capturedAuthCode := submatches[1]

				// One authcode should have been stored.
				require.Len(t, oauthStore.AuthorizeCodes, 1)

				// fosite authcodes are in the format `data.signature`, so grab the signature part, which is the lookup key in the storage interface
				authcodeDataAndSignature := strings.Split(capturedAuthCode, ".")
				require.Len(t, authcodeDataAndSignature, 2)

				// Get the authcode session back from storage so we can require that it was stored correctly.
				storedAuthorizeRequest, err := oauthStore.GetAuthorizeCodeSession(context.Background(), authcodeDataAndSignature[1], nil)
				require.NoError(t, err)

				// Check that storage returned the expected concrete data types.
				_, ok := storedAuthorizeRequest.(*fosite.Request)
				require.True(t, ok)
				storedSession, ok := storedAuthorizeRequest.GetSession().(*openid.DefaultSession)
				require.True(t, ok)

				// Check various fields of the stored data.
				require.Equal(t, "test-pinniped-username", storedSession.Claims.Subject)
			} else {
				require.Empty(t, rsp.Header().Values("Location"))
			}
		})
	}
}

type requestPath struct {
	upstreamIDPName, code, state *string
}

func newRequestPath() *requestPath {
	n := happyUpstreamIDPName
	c := "1234"
	s := "4321"
	return &requestPath{
		upstreamIDPName: &n,
		code:            &c,
		state:           &s,
	}
}

func (r *requestPath) WithUpstreamIDPName(name string) *requestPath {
	r.upstreamIDPName = &name
	return r
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
	path := fmt.Sprintf("/downstream-provider-name/callback/%s?", *r.upstreamIDPName)
	params := url.Values{}
	if r.code != nil {
		params.Add("code", *r.code)
	}
	if r.state != nil {
		params.Add("state", *r.state)
	}
	return path + params.Encode()
}
