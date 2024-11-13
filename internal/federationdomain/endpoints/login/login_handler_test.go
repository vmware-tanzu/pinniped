// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/auditid"
	"go.pinniped.dev/internal/federationdomain/endpoints/loginurl"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

const (
	htmlContentType = "text/html; charset=utf-8"
)

func TestLoginEndpoint(t *testing.T) {
	const (
		happyGetResult  = "<p>get handler result</p>"
		happyPostResult = "<p>post handler result</p>"

		happyUpstreamIDPName        = "upstream-idp-name"
		happyUpstreamIDPType        = "ldap"
		happyDownstreamCSRF         = "test-csrf"
		happyDownstreamPKCE         = "test-pkce"
		happyDownstreamNonce        = "test-nonce"
		happyDownstreamStateVersion = "2"

		downstreamClientID            = "pinniped-cli"
		happyDownstreamState          = "8b-state"
		downstreamNonce               = "some-nonce-value"
		downstreamPKCEChallenge       = "some-challenge"
		downstreamPKCEChallengeMethod = "S256"
		downstreamRedirectURI         = "http://127.0.0.1/callback"
	)

	happyDownstreamScopesRequested := []string{"openid"}
	happyDownstreamRequestParamsQuery := url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{strings.Join(happyDownstreamScopesRequested, " ")},
		"client_id":             []string{downstreamClientID},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{downstreamNonce},
		"code_challenge":        []string{downstreamPKCEChallenge},
		"code_challenge_method": []string{downstreamPKCEChallengeMethod},
		"redirect_uri":          []string{downstreamRedirectURI},
	}
	happyDownstreamRequestParams := happyDownstreamRequestParamsQuery.Encode()

	expectedHappyDecodedUpstreamStateParam := func() *oidc.UpstreamStateParamData {
		return &oidc.UpstreamStateParamData{
			UpstreamName:  happyUpstreamIDPName,
			UpstreamType:  happyUpstreamIDPType,
			AuthParams:    happyDownstreamRequestParams,
			Nonce:         happyDownstreamNonce,
			CSRFToken:     happyDownstreamCSRF,
			PKCECode:      happyDownstreamPKCE,
			FormatVersion: happyDownstreamStateVersion,
		}
	}

	expectedHappyDecodedUpstreamStateParamForActiveDirectory := func() *oidc.UpstreamStateParamData {
		s := expectedHappyDecodedUpstreamStateParam()
		s.UpstreamType = "activedirectory"
		return s
	}

	happyUpstreamStateParam := func() *oidctestutil.UpstreamStateParamBuilder {
		return &oidctestutil.UpstreamStateParamBuilder{
			U: happyUpstreamIDPName,
			T: happyUpstreamIDPType,
			P: happyDownstreamRequestParams,
			N: happyDownstreamNonce,
			C: happyDownstreamCSRF,
			K: happyDownstreamPKCE,
			V: happyDownstreamStateVersion,
		}
	}

	stateEncoderHashKey := []byte("fake-hash-secret")
	stateEncoderBlockKey := []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	cookieEncoderHashKey := []byte("fake-hash-secret2")
	cookieEncoderBlockKey := []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	happyStateCodec := securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateCodec.SetSerializer(securecookie.JSONEncoder{})
	happyCookieCodec := securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieCodec.SetSerializer(securecookie.JSONEncoder{})

	happyState := happyUpstreamStateParam().Build(t, happyStateCodec)
	happyPathWithState := newRequestPath().WithState(happyState).String()

	happyActiveDirectoryState := happyUpstreamStateParam().WithUpstreamIDPType("activedirectory").Build(t, happyStateCodec)

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	tests := []struct {
		name           string
		method         string
		path           string
		csrfCookie     string
		getHandlerErr  error
		postHandlerErr error

		wantStatus       int
		wantContentType  string
		wantBody         string
		wantEncodedState stateparam.Encoded
		wantDecodedState *oidc.UpstreamStateParamData
		wantAuditLogs    func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog
	}{
		{
			name:            "PUT method is invalid",
			method:          http.MethodPut,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PUT (try GET or POST)\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
				}
			},
		},
		{
			name:            "PATCH method is invalid",
			method:          http.MethodPatch,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PATCH (try GET or POST)\n",
		},
		{
			name:            "DELETE method is invalid",
			method:          http.MethodDelete,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: DELETE (try GET or POST)\n",
		},
		{
			name:            "HEAD method is invalid",
			method:          http.MethodHead,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: HEAD (try GET or POST)\n",
		},
		{
			name:            "CONNECT method is invalid",
			method:          http.MethodConnect,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: CONNECT (try GET or POST)\n",
		},
		{
			name:            "OPTIONS method is invalid",
			method:          http.MethodOptions,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: OPTIONS (try GET or POST)\n",
		},
		{
			name:            "TRACE method is invalid",
			method:          http.MethodTrace,
			path:            happyPathWithState,
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: TRACE (try GET or POST)\n",
		},
		{
			name:            "state param was not included on GET request",
			method:          http.MethodGet,
			path:            newRequestPath().WithoutState().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: state param not found\n",
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{},
					}),
				}
			},
		},
		{
			name:            "state param was not included on POST request",
			method:          http.MethodPost,
			path:            newRequestPath().WithoutState().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: state param not found\n",
		},
		{
			name:            "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason on GET request",
			method:          http.MethodGet,
			path:            newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state\n",
		},
		{
			name:            "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason on POST request",
			method:          http.MethodPost,
			path:            newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state\n",
		},
		{
			name:            "the CSRF cookie does not exist on GET request",
			method:          http.MethodGet,
			path:            happyPathWithState,
			csrfCookie:      "",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:            "the CSRF cookie does not exist on POST request",
			method:          http.MethodPost,
			path:            happyPathWithState,
			csrfCookie:      "",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:            "the CSRF cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason on GET request",
			method:          http.MethodGet,
			path:            happyPathWithState,
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:            "the CSRF cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason on POST request",
			method:          http.MethodPost,
			path:            happyPathWithState,
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:            "cookie csrf value does not match state csrf value on GET request",
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF value does not match\n",
		},
		{
			name:            "cookie csrf value does not match state csrf value on POST request",
			method:          http.MethodPost,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF value does not match\n",
		},
		{
			name:   "GET request when upstream IDP type in state param is not supported by this endpoint",
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithUpstreamIDPType("oidc").Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: not a supported upstream IDP type for this endpoint: \"oidc\"\n",
		},
		{
			name:   "GET request with invalid form",
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithUpstreamIDPType("oidc").Build(t, happyStateCodec),
			).String() + "&invalid;;param",
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error parsing request params\n",
		},
		{
			name:   "POST request when upstream IDP type in state param is not supported by this endpoint",
			method: http.MethodPost,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().WithUpstreamIDPType("oidc").Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: not a supported upstream IDP type for this endpoint: \"oidc\"\n",
		},
		{
			name:             "valid GET request when GET endpoint handler returns an error",
			method:           http.MethodGet,
			path:             happyPathWithState,
			csrfCookie:       happyCSRFCookie,
			getHandlerErr:    httperr.Newf(http.StatusInternalServerError, "some get error"),
			wantStatus:       http.StatusInternalServerError,
			wantContentType:  htmlContentType,
			wantBody:         "Internal Server Error: some get error\n",
			wantEncodedState: happyState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParam(),
		},
		{
			name:             "valid POST request when POST endpoint handler returns an error",
			method:           http.MethodPost,
			path:             happyPathWithState,
			csrfCookie:       happyCSRFCookie,
			postHandlerErr:   httperr.Newf(http.StatusInternalServerError, "some post error"),
			wantStatus:       http.StatusInternalServerError,
			wantContentType:  htmlContentType,
			wantBody:         "Internal Server Error: some post error\n",
			wantEncodedState: happyState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParam(),
		},
		{
			name:             "happy GET request with err param which can be set by the real POST handler on redirects back to the GET handler",
			method:           http.MethodGet,
			path:             happyPathWithState + "&" + loginurl.ErrParamName + "=" + string(loginurl.ShowBadUserPassErr),
			csrfCookie:       happyCSRFCookie,
			wantStatus:       http.StatusOK,
			wantContentType:  htmlContentType,
			wantBody:         happyGetResult,
			wantEncodedState: happyState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParam(),
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted", "err": "login_error"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:             "happy GET request for LDAP upstream",
			method:           http.MethodGet,
			path:             happyPathWithState,
			csrfCookie:       happyCSRFCookie,
			wantStatus:       http.StatusOK,
			wantContentType:  htmlContentType,
			wantBody:         happyGetResult,
			wantEncodedState: happyState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParam(),
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:             "happy POST request for LDAP upstream",
			method:           http.MethodPost,
			path:             happyPathWithState,
			csrfCookie:       happyCSRFCookie,
			wantStatus:       http.StatusOK,
			wantContentType:  htmlContentType,
			wantBody:         happyPostResult,
			wantEncodedState: happyState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParam(),
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:             "happy GET request for ActiveDirectory upstream",
			method:           http.MethodGet,
			path:             newRequestPath().WithState(happyActiveDirectoryState).String(),
			csrfCookie:       happyCSRFCookie,
			wantStatus:       http.StatusOK,
			wantContentType:  htmlContentType,
			wantBody:         happyGetResult,
			wantEncodedState: happyActiveDirectoryState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParamForActiveDirectory(),
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
		{
			name:             "happy POST request for ActiveDirectory upstream",
			method:           http.MethodPost,
			path:             newRequestPath().WithState(happyActiveDirectoryState).String(),
			csrfCookie:       happyCSRFCookie,
			wantStatus:       http.StatusOK,
			wantContentType:  htmlContentType,
			wantBody:         happyPostResult,
			wantEncodedState: happyActiveDirectoryState,
			wantDecodedState: expectedHappyDecodedUpstreamStateParamForActiveDirectory(),
			wantAuditLogs: func(encodedStateParam stateparam.Encoded) []testutil.WantedAuditLog {
				return []testutil.WantedAuditLog{
					testutil.WantAuditLog("HTTP Request Parameters", map[string]any{
						"params": map[string]any{"state": "redacted"},
					}),
					testutil.WantAuditLog("AuthorizeID From Parameters", map[string]any{
						"authorizeID": encodedStateParam.AuthorizeID(),
					}),
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(test.method, test.path, nil)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			req, _ = auditid.NewRequestWithAuditID(req, func() string { return "fake-audit-id" })
			rsp := httptest.NewRecorder()

			testGetHandler := func(
				w http.ResponseWriter,
				r *http.Request,
				encodedState stateparam.Encoded,
				decodedState *oidc.UpstreamStateParamData,
			) error {
				require.Equal(t, req, r)
				require.Equal(t, rsp, w)
				require.Equal(t, test.wantEncodedState, encodedState)
				require.Equal(t, test.wantDecodedState, decodedState)
				if test.getHandlerErr == nil {
					_, err := w.Write([]byte(happyGetResult))
					require.NoError(t, err)
				}
				return test.getHandlerErr
			}

			testPostHandler := func(
				w http.ResponseWriter,
				r *http.Request,
				encodedState stateparam.Encoded,
				decodedState *oidc.UpstreamStateParamData,
			) error {
				require.Equal(t, req, r)
				require.Equal(t, rsp, w)
				require.Equal(t, test.wantEncodedState, encodedState)
				require.Equal(t, test.wantDecodedState, decodedState)
				if test.postHandlerErr == nil {
					_, err := w.Write([]byte(happyPostResult))
					require.NoError(t, err)
				}
				return test.postHandlerErr
			}

			auditLogger, actualAuditLog := plog.TestAuditLogger(t)

			subject := NewHandler(happyStateCodec, happyCookieCodec, testGetHandler, testPostHandler, auditLogger)

			subject.ServeHTTP(rsp, req)

			if test.method == http.MethodPost {
				testutil.RequireSecurityHeadersWithFormPostPageCSPs(t, rsp)
			} else {
				testutil.RequireSecurityHeadersWithLoginPageCSPs(t, rsp)
			}

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)
			require.Equal(t, test.wantBody, rsp.Body.String())

			if test.wantAuditLogs != nil {
				wantAuditLogs := test.wantAuditLogs(testutil.GetStateParam(t, test.path))
				testutil.WantAuditIDOnEveryAuditLog(wantAuditLogs, "fake-audit-id")
				testutil.CompareAuditLogs(t, wantAuditLogs, actualAuditLog.String())
			}
		})
	}
}

type requestPath struct {
	state *stateparam.Encoded
}

func newRequestPath() *requestPath {
	return &requestPath{}
}

func (r *requestPath) WithState(state stateparam.Encoded) *requestPath {
	r.state = &state
	return r
}

func (r *requestPath) WithoutState() *requestPath {
	r.state = nil
	return r
}

func (r *requestPath) String() string {
	path := "/login?"
	params := url.Values{}
	if r.state != nil {
		params.Add("state", r.state.String())
	}
	return path + params.Encode()
}
