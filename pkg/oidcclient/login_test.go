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
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/mocks/mockkeyset"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
)

// mockSessionCache exists to avoid an import cycle if we generate mocks into another package.
type mockSessionCache struct {
	t               *testing.T
	getReturnsToken *Token
	sawGetKeys      []SessionCacheKey
	sawPutKeys      []SessionCacheKey
	sawPutTokens    []*Token
}

func (m *mockSessionCache) GetToken(key SessionCacheKey) *Token {
	m.t.Logf("saw mock session cache GetToken() with client ID %s", key.ClientID)
	m.sawGetKeys = append(m.sawGetKeys, key)
	return m.getReturnsToken
}

func (m *mockSessionCache) PutToken(key SessionCacheKey, token *Token) {
	m.t.Logf("saw mock session cache PutToken() with client ID %s and ID token %s", key.ClientID, token.IDToken.Token)
	m.sawPutKeys = append(m.sawPutKeys, key)
	m.sawPutTokens = append(m.sawPutTokens, token)
}

func TestLogin(t *testing.T) {
	time1 := time.Date(2035, 10, 12, 13, 14, 15, 16, time.UTC)
	time1Unix := int64(2075807775)
	require.Equal(t, time1Unix, time1.Add(2*time.Minute).Unix())

	testToken := Token{
		AccessToken: &AccessToken{
			Token:  "test-access-token",
			Expiry: metav1.NewTime(time1.Add(1 * time.Minute)),
		},
		RefreshToken: &RefreshToken{
			Token: "test-refresh-token",
		},
		IDToken: &IDToken{
			// Test JWT generated with https://smallstep.com/docs/cli/crypto/jwt/ (using time1Unix from above):
			// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti" --exp 2075807775
			Token:  "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImV4cCI6MjA3NTgwNzc3NSwiaWF0IjoxNjAzMzk5NTY4LCJpc3MiOiJ0ZXN0LWlzc3VlciIsImp0aSI6InRlc3QtanRpIiwibmJmIjoxNjAzMzk5NTY4LCJzdWIiOiJ0ZXN0LXVzZXIifQ.CdwUWQb6xELeFlC4u84K4rzks7YiDJiXxIo_SaRvCHBijxtil812RBRfPuAyYKJlGwFx1g-JYvkUg69X5NmvmLXkaOdHIKUAT7Nqa7yqd1xOAP9IlFj9qZM3Q7s8gWWW9da-_ryagzN4fyGfNfYeGhzIriSMaVpuBGz1eg6f-6VuuulnoiOpl8A0l50u0MdRjjsxRHuiR2loIhUxoIQQ9xN8w53UiP0R1uz8_uV0_K93RSq37aPjsnCXRLwUUb3azkRVe6B9EUW1ihthQ-KfRaU1iq2rY1m5UqNzf0NqDXCrN5SF-GVxOhKXJTsN4-PABfJBjqxg6dGUGeIa2JhFcA",
			Expiry: metav1.NewTime(time1.Add(2 * time.Minute)),
		},
	}

	// Start a test server that returns 500 errors
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "some discovery error", http.StatusInternalServerError)
	}))
	t.Cleanup(errorServer.Close)

	// Start a test server that returns a real keyset and answers refresh requests.
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
		wantToken *Token
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
					cache := &mockSessionCache{t: t, getReturnsToken: &Token{
						IDToken: &IDToken{
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
					cache := &mockSessionCache{t: t, getReturnsToken: &Token{
						IDToken: &IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &RefreshToken{Token: "test-refresh-token"},
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

					h.oidcDiscover = func(ctx context.Context, iss string) (discoveryI, error) {
						provider, err := oidc.NewProvider(ctx, iss)
						require.NoError(t, err)
						return &mockDiscovery{provider: provider}, nil
					}
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
					cache := &mockSessionCache{t: t, getReturnsToken: &Token{
						IDToken: &IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &RefreshToken{Token: "test-refresh-token-returning-invalid-id-token"},
					}}
					t.Cleanup(func() {
						require.Empty(t, cache.sawPutKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					h.cache = cache

					h.oidcDiscover = func(ctx context.Context, iss string) (discoveryI, error) {
						provider, err := oidc.NewProvider(ctx, iss)
						require.NoError(t, err)
						return &mockDiscovery{provider: provider}, nil
					}

					return nil
				}
			},
			wantErr: "received invalid ID token: oidc: malformed jwt: square/go-jose: compact JWS format must have three parts",
		},
		{
			name:     "session cache hit but refresh fails",
			issuer:   successServer.URL,
			clientID: "not-the-test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &Token{
						IDToken: &IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.Now(), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &RefreshToken{Token: "test-refresh-token"},
					}}
					t.Cleanup(func() {
						require.Empty(t, cache.sawPutKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					h.cache = cache

					h.oidcDiscover = func(ctx context.Context, iss string) (discoveryI, error) {
						provider, err := oidc.NewProvider(ctx, iss)
						require.NoError(t, err)
						return &mockDiscovery{provider: provider}, nil
					}

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
						require.Equal(t, []*Token{&testToken}, cache.sawPutTokens)
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
		returnIDTok    string
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
			wantErr:        "could not complete code exchange: oauth2: cannot fetch token: 403 Forbidden\nResponse: invalid authorization code\n",
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "missing ID token",
			query:          "state=test-state&code=valid",
			returnIDTok:    "",
			wantErr:        "received response missing ID token",
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid ID token",
			query:          "state=test-state&code=valid",
			returnIDTok:    "invalid-jwt",
			wantErr:        "received invalid ID token: oidc: malformed jwt: square/go-jose: compact JWS format must have three parts",
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:  "invalid access token hash",
			query: "state=test-state&code=valid",

			// Test JWT generated with https://smallstep.com/docs/cli/crypto/jwt/:
			// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"at_hash": "invalid-at-hash"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
			returnIDTok: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdF9oYXNoIjoiaW52YWxpZC1hdC1oYXNoIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE2MDIyODM3OTEsImp0aSI6InRlc3QtanRpIiwibmJmIjoxNjAyMjgzNzkxLCJzdWIiOiJ0ZXN0LXVzZXIifQ.jryXr4jiwcf79wBLaHpjdclEYHoUFGhvTu95QyA6Hnk9NQ0x1vsWYurtj7a8uKydNPryC_HNZi9QTAE_tRIJjycseog3695-5y4B4EZlqL-a94rdOtffuF2O_lnPbKvoja9EKNrp0kLBCftFRHhLAEwuP0N9E5padZwPpIGK0yE_JqljnYgCySvzsQu7tasR38yaULny13h3mtp2WRHPG5DrLyuBuF8Z01hSgRi5hGcVpgzTwBgV5-eMaSUCUo-ZDkqUsLQI6dVlaikCSKYZRb53HeexH0tB_R9PJJHY7mIr-rS76kkQEx9pLuVnheIH9Oc6zbdYWg-zWMijopA8Pg",

			wantErr:        "received invalid ID token: access token hash does not match value in ID token",
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:  "invalid nonce",
			query: "state=test-state&code=valid",

			// Test JWT generated with https://smallstep.com/docs/cli/crypto/jwt/:
			// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"nonce": "invalid-nonce"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
			returnIDTok: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTYwMjI4Mzc0MSwianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MDIyODM3NDEsIm5vbmNlIjoiaW52YWxpZC1ub25jZSIsInN1YiI6InRlc3QtdXNlciJ9.PRpq-7j5djaIAkraL-8t8ad9Xm4hM8RW67gyD1VIe0BecWeBFxsTuh3SZVKM9zmcwTgjudsyn8kQOwipDa49IN4PV8FcJA_uUJZi2wiqGJUSTG2K5I89doV_7e0RM1ZYIDDW1G2heKJNW7MbKkX7iEPr7u4MyEzswcPcupbyDA-CQFeL95vgwawoqa6yO94ympTbozqiNfj6Xyw_nHtThQnstjWsJZ9s2mUgppZezZv4HZYTQ7c3e_bzwhWgCzh2CSDJn9_Ra_n_4GcVkpHbsHTP35dFsnf0vactPx6CAu6A1-Apk-BruCktpZ3B4Ercf1UnUOHdGqzQKJtqvB03xQ",

			wantHTTPStatus: http.StatusBadRequest,
			wantErr:        `received ID token with invalid nonce: invalid nonce (expected "test-nonce", got "invalid-nonce")`,
		},
		{
			name:  "valid",
			query: "state=test-state&code=valid",

			// Test JWT generated with https://smallstep.com/docs/cli/crypto/jwt/:
			// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"nonce": "test-nonce"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
			returnIDTok: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTYwMjUzMTU2NywianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MDI1MzE1NjcsIm5vbmNlIjoidGVzdC1ub25jZSIsInN1YiI6InRlc3QtdXNlciJ9.LbOA31iwJZBM4ayY5Oud-HArLXbmtAIhZv_LazDqbzA2Iw87RxoBemfiPUJeAesdnO1LKSjBwbltZwtjvbLWHp1R5tqrSMr_hl2OyZv1cpEX-9QaTcQILJ5qR00riRLz34ZCQFyF-FfQpP1r4dNqFrxHuiBwKuPE7zogc83ZYJgAQM5Fao9rIRY9JStL_3pURa9JnnSHFlkLvFYv3TKEUyvnW4pWvYZcsGI7mys43vuSjpG7ZSrW3vCxovuIpXYqAhamZL_XexWUsXvi3ej9HNlhnhOFhN4fuPSc0PWDWaN0CLWmoo8gvOdQWo5A4GD4bNGBzjYOd-pYqsDfseRt1Q",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.NoError(t, r.ParseForm())
				require.Equal(t, "test-client-id", r.Form.Get("client_id"))
				require.Equal(t, "test-pkce", r.Form.Get("code_verifier"))
				require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
				require.NotEmpty(t, r.Form.Get("code"))
				if r.Form.Get("code") != "valid" {
					http.Error(w, "invalid authorization code", http.StatusForbidden)
					return
				}
				var response struct {
					oauth2.Token
					IDToken string `json:"id_token,omitempty"`
				}
				response.AccessToken = "test-access-token"
				response.Expiry = time.Now().Add(time.Hour)
				response.IDToken = tt.returnIDTok
				w.Header().Set("content-type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(&response))
			}))
			t.Cleanup(tokenServer.Close)

			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
				oauth2Config: &oauth2.Config{
					ClientID:    "test-client-id",
					RedirectURL: "http://localhost:12345/callback",
					Endpoint: oauth2.Endpoint{
						TokenURL:  tokenServer.URL,
						AuthStyle: oauth2.AuthStyleInParams,
					},
				},
				idTokenVerifier: mockVerifier(),
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
				require.Equal(t, result.token.IDToken.Token, tt.returnIDTok)
			}
		})
	}
}

// mockVerifier returns an *oidc.IDTokenVerifier that validates any correctly serialized JWT without doing much else.
func mockVerifier() *oidc.IDTokenVerifier {
	mockKeySet := mockkeyset.NewMockKeySet(gomock.NewController(nil))
	mockKeySet.EXPECT().VerifySignature(gomock.Any(), gomock.Any()).
		AnyTimes().
		DoAndReturn(func(ctx context.Context, jwt string) ([]byte, error) {
			jws, err := jose.ParseSigned(jwt)
			if err != nil {
				return nil, err
			}
			return jws.UnsafePayloadWithoutVerification(), nil
		})

	return oidc.NewVerifier("", mockKeySet, &oidc.Config{
		SkipIssuerCheck:   true,
		SkipExpiryCheck:   true,
		SkipClientIDCheck: true,
	})
}

type mockDiscovery struct{ provider *oidc.Provider }

func (m *mockDiscovery) Endpoint() oauth2.Endpoint { return m.provider.Endpoint() }

func (m *mockDiscovery) Verifier(config *oidc.Config) *oidc.IDTokenVerifier { return mockVerifier() }
