// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/mocks/mockupstreamoidcidentityprovider"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
)

// mockSessionCache exists to avoid an import cycle if we generate mocks into another package.
type mockSessionCache struct {
	t               *testing.T
	getReturnsToken *oidctypes.Token
	sawGetKeys      []SessionCacheKey
	sawPutKeys      []SessionCacheKey
	sawPutTokens    []*oidctypes.Token
}

func (m *mockSessionCache) GetToken(key SessionCacheKey) *oidctypes.Token {
	m.t.Logf("saw mock session cache GetToken() with client ID %s", key.ClientID)
	m.sawGetKeys = append(m.sawGetKeys, key)
	return m.getReturnsToken
}

func (m *mockSessionCache) PutToken(key SessionCacheKey, token *oidctypes.Token) {
	m.t.Logf("saw mock session cache PutToken() with client ID %s and ID token %s", key.ClientID, token.IDToken.Token)
	m.sawPutKeys = append(m.sawPutKeys, key)
	m.sawPutTokens = append(m.sawPutTokens, token)
}

func TestLogin(t *testing.T) {
	time1 := time.Date(2035, 10, 12, 13, 14, 15, 16, time.UTC)
	time1Unix := int64(2075807775)
	require.Equal(t, time1Unix, time1.Add(2*time.Minute).Unix())

	testToken := oidctypes.Token{
		AccessToken:  &oidctypes.AccessToken{Token: "test-access-token", Expiry: metav1.NewTime(time1.Add(1 * time.Minute))},
		RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
		IDToken:      &oidctypes.IDToken{Token: "test-id-token", Expiry: metav1.NewTime(time1.Add(2 * time.Minute))},
	}

	// Start a test server that returns 500 errors
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "some discovery error", http.StatusInternalServerError)
	}))
	t.Cleanup(errorServer.Close)

	// Start a test server that returns a real discovery document and answers refresh requests.
	providerMux := http.NewServeMux()
	successServer := httptest.NewServer(providerMux)
	t.Cleanup(successServer.Close)
	providerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer   string `json:"issuer"`
			AuthURL  string `json:"authorization_endpoint"`
			TokenURL string `json:"token_endpoint"`
			JWKSURL  string `json:"jwks_uri"`
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   successServer.URL,
			AuthURL:  successServer.URL + "/authorize",
			TokenURL: successServer.URL + "/token",
			JWKSURL:  successServer.URL + "/keys",
		})
	})
	providerMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_id") != "test-client-id" {
			http.Error(w, "expected client_id 'test-client-id'", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "expected refresh_token grant type", http.StatusBadRequest)
			return
		}

		var response struct {
			oauth2.Token
			IDToken   string `json:"id_token,omitempty"`
			ExpiresIn int64  `json:"expires_in"`
		}
		response.AccessToken = testToken.AccessToken.Token
		response.ExpiresIn = int64(time.Until(testToken.AccessToken.Expiry.Time).Seconds())
		response.RefreshToken = testToken.RefreshToken.Token
		response.IDToken = testToken.IDToken.Token

		if r.Form.Get("refresh_token") == "test-refresh-token-returning-invalid-id-token" {
			response.IDToken = "not a valid JWT"
		} else if r.Form.Get("refresh_token") != "test-refresh-token" {
			http.Error(w, "expected refresh_token to be 'test-refresh-token'", http.StatusBadRequest)
			return
		}

		w.Header().Set("content-type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(&response))
	})

	tests := []struct {
		name      string
		opt       func(t *testing.T) Option
		issuer    string
		clientID  string
		wantErr   string
		wantToken *oidctypes.Token
	}{
		{
			name: "option error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return fmt.Errorf("some option error")
				}
			},
			wantErr: "some option error",
		},
		{
			name: "error generating state",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "", fmt.Errorf("some error generating state") }
					return nil
				}
			},
			wantErr: "some error generating state",
		},
		{
			name: "error generating nonce",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateNonce = func() (nonce.Nonce, error) { return "", fmt.Errorf("some error generating nonce") }
					return nil
				}
			},
			wantErr: "some error generating nonce",
		},
		{
			name: "error generating PKCE",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generatePKCE = func() (pkce.Code, error) { return "", fmt.Errorf("some error generating PKCE") }
					return nil
				}
			},
			wantErr: "some error generating PKCE",
		},
		{
			name:     "session cache hit but token expired",
			issuer:   "test-issuer",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(time.Now()), // less than Now() + minIDTokenValidity
						},
					}}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      "test-issuer",
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					return WithSessionCache(cache)(h)
				}
			},
			wantErr: `could not perform OIDC discovery for "test-issuer": Get "test-issuer/.well-known/openid-configuration": unsupported protocol scheme ""`,
		},
		{
			name:     "session cache hit with valid token",
			issuer:   "test-issuer",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      "test-issuer",
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					return WithSessionCache(cache)(h)
				}
			},
			wantToken: &testToken,
		},
		{
			name: "discovery failure",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error { return nil }
			},
			issuer:  errorServer.URL,
			wantErr: fmt.Sprintf("could not perform OIDC discovery for %q: 500 Internal Server Error: some discovery error\n", errorServer.URL),
		},
		{
			name:     "session cache hit with refreshable token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.getProvider = func(config *oauth2.Config, o *oidc.Provider) provider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateToken(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce("")).
							Return(testToken, nil, nil)
						return mock
					}

					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
					}}
					t.Cleanup(func() {
						cacheKey := SessionCacheKey{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Len(t, cache.sawPutTokens, 1)
						require.Equal(t, testToken.IDToken.Token, cache.sawPutTokens[0].IDToken.Token)
					})
					h.cache = cache
					return nil
				}
			},
			wantToken: &testToken,
		},
		{
			name:     "session cache hit but refresh returns invalid token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.getProvider = func(config *oauth2.Config, o *oidc.Provider) provider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateToken(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce("")).
							Return(oidctypes.Token{}, nil, fmt.Errorf("some validation error"))
						return mock
					}

					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token-returning-invalid-id-token"},
					}}
					t.Cleanup(func() {
						require.Empty(t, cache.sawPutKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					h.cache = cache

					return nil
				}
			},
			wantErr: "some validation error",
		},
		{
			name:     "session cache hit but refresh fails",
			issuer:   successServer.URL,
			clientID: "not-the-test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
					}}
					t.Cleanup(func() {
						require.Empty(t, cache.sawPutKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					h.cache = cache

					h.listenAddr = "invalid-listen-address"

					return nil
				}
			},
			// Expect this to fall through to the authorization code flow, so it fails here.
			wantErr: "could not open callback listener: listen tcp: address invalid-listen-address: missing port in address",
		},
		{
			name: "listen failure",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.listenAddr = "invalid-listen-address"
					return nil
				}
			},
			issuer:  successServer.URL,
			wantErr: "could not open callback listener: listen tcp: address invalid-listen-address: missing port in address",
		},
		{
			name: "browser open failure",
			opt: func(t *testing.T) Option {
				return WithBrowserOpen(func(url string) error {
					return fmt.Errorf("some browser open error")
				})
			},
			issuer:  successServer.URL,
			wantErr: "could not open browser: some browser open error",
		},
		{
			name: "timeout waiting for callback",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					ctx, cancel := context.WithCancel(h.ctx)
					h.ctx = ctx

					h.openURL = func(_ string) error {
						cancel()
						return nil
					}
					return nil
				}
			},
			issuer:  successServer.URL,
			wantErr: "timed out waiting for token callback: context canceled",
		},
		{
			name: "callback returns error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.openURL = func(_ string) error {
						go func() {
							h.callbacks <- callbackResult{err: fmt.Errorf("some callback error")}
						}()
						return nil
					}
					return nil
				}
			},
			issuer:  successServer.URL,
			wantErr: "error handling callback: some callback error",
		},
		{
			name:     "callback returns success",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:      successServer.URL,
						ClientID:    "test-client-id",
						Scopes:      []string{"test-scope"},
						RedirectURI: "http://localhost:0/callback",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithClient(&http.Client{Timeout: 10 * time.Second})(h))

					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
							// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
							// VVaezYqum7reIhoavCHD1n2d+piN3r/mywoYj7fCR7g
							"code_challenge":        []string{"VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"},
							"code_challenge_method": []string{"S256"},
							"response_type":         []string{"code"},
							"scope":                 []string{"test-scope"},
							"nonce":                 []string{"test-nonce"},
							"state":                 []string{"test-state"},
							"access_type":           []string{"offline"},
							"client_id":             []string{"test-client-id"},
						}, actualParams)

						parsedActualURL.RawQuery = ""
						require.Equal(t, successServer.URL+"/authorize", parsedActualURL.String())

						go func() {
							h.callbacks <- callbackResult{token: &testToken}
						}()
						return nil
					}
					return nil
				}
			},
			issuer:    successServer.URL,
			wantToken: &testToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tok, err := Login(tt.issuer, tt.clientID,
				WithContext(context.Background()),
				WithListenPort(0),
				WithScopes([]string{"test-scope"}),
				tt.opt(t),
			)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, tok)
				return
			}
			require.NoError(t, err)

			if tt.wantToken == nil {
				require.Nil(t, tok)
				return
			}
			require.NotNil(t, tok)

			if want := tt.wantToken.AccessToken; want != nil {
				require.NotNil(t, tok.AccessToken)
				require.Equal(t, want.Token, tok.AccessToken.Token)
				require.Equal(t, want.Type, tok.AccessToken.Type)
				testutil.RequireTimeInDelta(t, want.Expiry.Time, tok.AccessToken.Expiry.Time, 5*time.Second)
			} else {
				assert.Nil(t, tok.AccessToken)
			}
			require.Equal(t, tt.wantToken.RefreshToken, tok.RefreshToken)
			if want := tt.wantToken.IDToken; want != nil {
				require.NotNil(t, tok.IDToken)
				require.Equal(t, want.Token, tok.IDToken.Token)
				testutil.RequireTimeInDelta(t, want.Expiry.Time, tok.IDToken.Expiry.Time, 5*time.Second)
			} else {
				assert.Nil(t, tok.IDToken)
			}
		})
	}
}

func TestHandleAuthCodeCallback(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		query          string
		opt            func(t *testing.T) Option
		wantErr        string
		wantHTTPStatus int
	}{
		{
			name:           "wrong method",
			method:         "POST",
			query:          "",
			wantErr:        "wanted GET",
			wantHTTPStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid state",
			query:          "state=invalid",
			wantErr:        "missing or invalid state parameter",
			wantHTTPStatus: http.StatusForbidden,
		},
		{
			name:           "error code from provider",
			query:          "state=test-state&error=some_error",
			wantErr:        `login failed with code "some_error"`,
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid code",
			query:          "state=test-state&code=invalid",
			wantErr:        "could not complete code exchange: some exchange error",
			wantHTTPStatus: http.StatusBadRequest,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.getProvider = func(config *oauth2.Config, provider *oidc.Provider) provider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "invalid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce")).
							Return(oidctypes.Token{}, nil, fmt.Errorf("some exchange error"))
						return mock
					}
					return nil
				}
			},
		},
		{
			name:  "valid",
			query: "state=test-state&code=valid",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.getProvider = func(config *oauth2.Config, provider *oidc.Provider) provider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce")).
							Return(oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil, nil)
						return mock
					}
					return nil
				}
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
			}
			if tt.opt != nil {
				require.NoError(t, tt.opt(t)(h))
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, "GET", "/test-callback", nil)
			require.NoError(t, err)
			req.URL.RawQuery = tt.query
			if tt.method != "" {
				req.Method = tt.method
			}

			err = h.handleAuthCodeCallback(resp, req)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				if tt.wantHTTPStatus != 0 {
					rec := httptest.NewRecorder()
					err.(httperr.Responder).Respond(rec)
					require.Equal(t, tt.wantHTTPStatus, rec.Code)
				}
			} else {
				require.NoError(t, err)
			}

			select {
			case <-time.After(1 * time.Second):
				require.Fail(t, "timed out waiting to receive from callbacks channel")
			case result := <-h.callbacks:
				if tt.wantErr != "" {
					require.EqualError(t, result.err, tt.wantErr)
					return
				}
				require.NoError(t, result.err)
				require.NotNil(t, result.token)
				require.Equal(t, result.token.IDToken.Token, "test-id-token")
			}
		})
	}
}

func mockUpstream(t *testing.T) *mockupstreamoidcidentityprovider.MockUpstreamOIDCIdentityProviderI {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	return mockupstreamoidcidentityprovider.NewMockUpstreamOIDCIdentityProviderI(ctrl)
}

// hasAccessTokenMatcher is a gomock.Matcher that expects an *oauth2.Token with a particular access token.
type hasAccessTokenMatcher struct{ expected string }

func (m hasAccessTokenMatcher) Matches(arg interface{}) bool {
	return arg.(*oauth2.Token).AccessToken == m.expected
}

func (m hasAccessTokenMatcher) Got(got interface{}) string {
	return got.(*oauth2.Token).AccessToken
}

func (m hasAccessTokenMatcher) String() string {
	return m.expected
}

func HasAccessToken(expected string) gomock.Matcher {
	return hasAccessTokenMatcher{expected: expected}
}
