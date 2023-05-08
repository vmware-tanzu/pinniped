// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/mocks/mockupstreamoidcidentityprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/testlogger"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/internal/upstreamoidc"
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

func newClientForServer(server *httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	caPEMData := tlsserver.TLSTestServerCA(server)
	pool.AppendCertsFromPEM(caPEMData)
	return phttp.Default(pool)
}

func TestLogin(t *testing.T) { //nolint:gocyclo
	time1 := time.Date(2035, 10, 12, 13, 14, 15, 16, time.UTC)
	time1Unix := int64(2075807775)
	require.Equal(t, time1Unix, time1.Add(2*time.Minute).Unix())

	testToken := oidctypes.Token{
		AccessToken:  &oidctypes.AccessToken{Token: "test-access-token", Expiry: metav1.NewTime(time1.Add(1 * time.Minute))},
		RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
		IDToken:      &oidctypes.IDToken{Token: "test-id-token", Expiry: metav1.NewTime(time1.Add(2 * time.Minute))},
	}

	testExchangedToken := oidctypes.Token{
		IDToken: &oidctypes.IDToken{Token: "test-id-token-with-requested-audience", Expiry: metav1.NewTime(time1.Add(3 * time.Minute))},
	}

	// Start a test server that returns 500 errors.
	errorServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "some discovery error", http.StatusInternalServerError)
	}), nil)

	// Start a test server that returns discovery data with a broken response_modes_supported value.
	brokenResponseModeMux := http.NewServeMux()
	brokenResponseModeServer := tlsserver.TLSTestServer(t, brokenResponseModeMux, nil)
	brokenResponseModeMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer                 string `json:"issuer"`
			AuthURL                string `json:"authorization_endpoint"`
			TokenURL               string `json:"token_endpoint"`
			ResponseModesSupported string `json:"response_modes_supported"` // Wrong type (should be []string).
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:                 brokenResponseModeServer.URL,
			AuthURL:                brokenResponseModeServer.URL + "/authorize",
			TokenURL:               brokenResponseModeServer.URL + "/token",
			ResponseModesSupported: "invalid",
		})
	})

	// Start a test server that returns discovery data with a broken token URL.
	brokenTokenURLMux := http.NewServeMux()
	brokenTokenURLServer := tlsserver.TLSTestServer(t, brokenTokenURLMux, nil)
	brokenTokenURLMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer   string `json:"issuer"`
			AuthURL  string `json:"authorization_endpoint"`
			TokenURL string `json:"token_endpoint"`
			JWKSURL  string `json:"jwks_uri"`
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   brokenTokenURLServer.URL,
			AuthURL:  brokenTokenURLServer.URL + "/authorize",
			TokenURL: "%",
			JWKSURL:  brokenTokenURLServer.URL + "/keys",
		})
	})

	// Start a test server that returns discovery data with an insecure token URL.
	insecureTokenURLMux := http.NewServeMux()
	insecureTokenURLServer := tlsserver.TLSTestServer(t, insecureTokenURLMux, nil)
	insecureTokenURLMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer   string `json:"issuer"`
			AuthURL  string `json:"authorization_endpoint"`
			TokenURL string `json:"token_endpoint"`
			JWKSURL  string `json:"jwks_uri"`
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   insecureTokenURLServer.URL,
			AuthURL:  insecureTokenURLServer.URL + "/authorize",
			TokenURL: "http://insecure-issuer.com",
			JWKSURL:  insecureTokenURLServer.URL + "/keys",
		})
	})

	// Start a test server that returns discovery data with a broken authorize URL.
	brokenAuthURLMux := http.NewServeMux()
	brokenAuthURLServer := tlsserver.TLSTestServer(t, brokenAuthURLMux, nil)
	brokenAuthURLMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer   string `json:"issuer"`
			AuthURL  string `json:"authorization_endpoint"`
			TokenURL string `json:"token_endpoint"`
			JWKSURL  string `json:"jwks_uri"`
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   brokenAuthURLServer.URL,
			AuthURL:  `%`,
			TokenURL: brokenAuthURLServer.URL + "/token",
			JWKSURL:  brokenAuthURLServer.URL + "/keys",
		})
	})

	// Start a test server that returns discovery data with an insecure authorize URL.
	insecureAuthURLMux := http.NewServeMux()
	insecureAuthURLServer := tlsserver.TLSTestServer(t, insecureAuthURLMux, nil)
	insecureAuthURLMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		type providerJSON struct {
			Issuer   string `json:"issuer"`
			AuthURL  string `json:"authorization_endpoint"`
			TokenURL string `json:"token_endpoint"`
			JWKSURL  string `json:"jwks_uri"`
		}
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:   insecureAuthURLServer.URL,
			AuthURL:  "http://insecure-issuer.com",
			TokenURL: insecureAuthURLServer.URL + "/token",
			JWKSURL:  insecureAuthURLServer.URL + "/keys",
		})
	})

	discoveryHandler := func(server *httptest.Server, responseModes []string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&struct {
				Issuer                 string   `json:"issuer"`
				AuthURL                string   `json:"authorization_endpoint"`
				TokenURL               string   `json:"token_endpoint"`
				JWKSURL                string   `json:"jwks_uri"`
				ResponseModesSupported []string `json:"response_modes_supported,omitempty"`
			}{
				Issuer:                 server.URL,
				AuthURL:                server.URL + "/authorize",
				TokenURL:               server.URL + "/token",
				JWKSURL:                server.URL + "/keys",
				ResponseModesSupported: responseModes,
			})
		}
	}
	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var response struct {
			oauth2.Token
			IDToken         string `json:"id_token,omitempty"`
			ExpiresIn       int64  `json:"expires_in"`
			IssuedTokenType string `json:"issued_token_type,omitempty"`
		}

		switch r.Form.Get("grant_type") {
		case "refresh_token":
			if r.Form.Get("client_id") != "test-client-id" {
				http.Error(w, "expected client_id 'test-client-id'", http.StatusBadRequest)
				return
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

		case "urn:ietf:params:oauth:grant-type:token-exchange":
			if r.Form.Get("client_id") != "test-client-id" {
				http.Error(w, "bad client_id", http.StatusBadRequest)
				return
			}

			switch r.Form.Get("audience") {
			case "test-audience-produce-invalid-http-response":
				http.Redirect(w, r, "%", http.StatusTemporaryRedirect)
				return
			case "test-audience-produce-http-400":
				http.Error(w, "some server error", http.StatusBadRequest)
				return
			case "test-audience-produce-invalid-content-type":
				w.Header().Set("content-type", "invalid/invalid;=")
				return
			case "test-audience-produce-wrong-content-type":
				w.Header().Set("content-type", "invalid")
				return
			case "test-audience-produce-invalid-json":
				w.Header().Set("content-type", "application/json;charset=UTF-8")
				_, _ = w.Write([]byte(`{`))
				return
			case "test-audience-produce-invalid-tokentype":
				response.TokenType = "invalid"
			case "test-audience-produce-invalid-issuedtokentype":
				response.TokenType = "N_A"
				response.IssuedTokenType = "invalid"
			case "test-audience-produce-invalid-jwt":
				response.TokenType = "N_A"
				response.IssuedTokenType = "urn:ietf:params:oauth:token-type:jwt"
				response.AccessToken = "not-a-valid-jwt"
			default:
				response.TokenType = "N_A"
				response.IssuedTokenType = "urn:ietf:params:oauth:token-type:jwt"
				response.AccessToken = testExchangedToken.IDToken.Token
			}

		default:
			http.Error(w, fmt.Sprintf("invalid grant_type %q", r.Form.Get("grant_type")), http.StatusBadRequest)
			return
		}

		w.Header().Set("content-type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(&response))
	}

	// Start a test server that returns a real discovery document and answers refresh requests.
	providerMux := http.NewServeMux()
	successServer := tlsserver.TLSTestServer(t, providerMux, nil)
	providerMux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(successServer, nil))
	providerMux.HandleFunc("/token", tokenHandler)

	// Start a test server that returns a real discovery document and answers refresh requests, _and_ supports form_mode=post.
	formPostProviderMux := http.NewServeMux()
	formPostSuccessServer := tlsserver.TLSTestServer(t, formPostProviderMux, nil)
	formPostProviderMux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(formPostSuccessServer, []string{"query", "form_post"}))
	formPostProviderMux.HandleFunc("/token", tokenHandler)

	defaultDiscoveryResponse := func(req *http.Request) (*http.Response, error) {
		// Call the handler function from the test server to calculate the response.
		handler, _ := providerMux.Handler(req)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Result(), nil
	}

	defaultLDAPTestOpts := func(t *testing.T, h *handlerState, authResponse *http.Response, authError error) error {
		h.generateState = func() (state.State, error) { return "test-state", nil }
		h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
		h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
		h.promptForValue = func(_ context.Context, promptLabel string) (string, error) { return "some-upstream-username", nil }
		h.promptForSecret = func(_ string) (string, error) { return "some-upstream-password", nil }

		cache := &mockSessionCache{t: t, getReturnsToken: nil}
		cacheKey := SessionCacheKey{
			Issuer:      successServer.URL,
			ClientID:    "test-client-id",
			Scopes:      []string{"test-scope"},
			RedirectURI: "http://localhost:0/callback",
		}
		t.Cleanup(func() {
			require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
		})
		require.NoError(t, WithSessionCache(cache)(h))
		require.NoError(t, WithCLISendingCredentials()(h))
		require.NoError(t, WithUpstreamIdentityProvider("some-upstream-name", "ldap")(h))
		require.NoError(t, WithClient(newClientForServer(successServer))(h))

		require.NoError(t, WithClient(&http.Client{
			Transport: roundtripper.Func(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
				case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
					return defaultDiscoveryResponse(req)
				case "https://" + successServer.Listener.Addr().String() + "/authorize":
					return authResponse, authError
				default:
					require.FailNow(t, fmt.Sprintf("saw unexpected http call from the CLI: %s", req.URL.String()))
					return nil, nil
				}
			}),
		})(h))
		return nil
	}

	tests := []struct {
		name      string
		opt       func(t *testing.T) Option
		issuer    string
		clientID  string
		wantErr   string
		wantToken *oidctypes.Token
		wantLogs  []string
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
			name:     "issuer is not https",
			issuer:   "http://insecure-issuer.com",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return nil
				}
			},
			wantLogs: nil,
			wantErr:  `issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name:     "issuer is not a valid URL",
			issuer:   "%",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return nil
				}
			},
			wantLogs: nil,
			wantErr:  `issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name:     "session cache hit but token expired",
			issuer:   errorServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(errorServer))(h))
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(time.Now()), // less than Now() + minIDTokenValidity
						},
					}}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      errorServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					return WithSessionCache(cache)(h)
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + errorServer.URL + "\""},
			wantErr:  "could not perform OIDC discovery for \"" + errorServer.URL + "\": 500 Internal Server Error: some discovery error\n",
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
			wantLogs:  []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\""},
			wantToken: &testToken,
		},
		{
			name: "discovery failure due to 500 error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(errorServer))(h))
					return nil
				}
			},
			issuer:   errorServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + errorServer.URL + "\""},
			wantErr:  fmt.Sprintf("could not perform OIDC discovery for %q: 500 Internal Server Error: some discovery error\n", errorServer.URL),
		},
		{
			name: "discovery failure due to invalid response_modes_supported",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(brokenResponseModeServer))(h))
					return nil
				}
			},
			issuer:   brokenResponseModeServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + brokenResponseModeServer.URL + "\""},
			wantErr:  fmt.Sprintf("could not decode response_modes_supported in OIDC discovery from %q: json: cannot unmarshal string into Go struct field .response_modes_supported of type []string", brokenResponseModeServer.URL),
		},
		{
			name:     "session cache hit with refreshable token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))

					h.getProvider = func(config *oauth2.Config, provider *oidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateTokenAndMergeWithUserInfo(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce(""), true, false).
							Return(&testToken, nil)
						mock.EXPECT().
							PerformRefresh(gomock.Any(), testToken.RefreshToken.Token).
							DoAndReturn(func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
								// Call the real production code to perform a refresh.
								return upstreamoidc.New(config, provider, client).PerformRefresh(ctx, refreshToken)
							})
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
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Refreshing cached token.\""},
			wantToken: &testToken,
		},
		{
			name:     "session cache hit but refresh returns invalid token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))

					h.getProvider = func(config *oauth2.Config, provider *oidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateTokenAndMergeWithUserInfo(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce(""), true, false).
							Return(nil, fmt.Errorf("some validation error"))
						mock.EXPECT().
							PerformRefresh(gomock.Any(), "test-refresh-token-returning-invalid-id-token").
							DoAndReturn(func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
								// Call the real production code to perform a refresh.
								return upstreamoidc.New(config, provider, client).PerformRefresh(ctx, refreshToken)
							})
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
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Refreshing cached token.\""},
			wantErr: "some validation error",
		},
		{
			name:     "session cache hit but refresh fails",
			issuer:   successServer.URL,
			clientID: "not-the-test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))

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

					h.listen = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("some listen error") }
					h.isTTY = func(int) bool { return false }
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached token."`,
				`"level"=4 "msg"="Pinniped: Refresh failed."  "error"="oauth2: cannot fetch token: 400 Bad Request\nResponse: expected client_id 'test-client-id'\n"`,
				`"msg"="could not open callback listener" "error"="some listen error"`,
			},
			// Expect this to fall through to the authorization code flow, so it fails here.
			wantErr: "login failed: must have either a localhost listener or stdin must be a TTY",
		},
		{
			name: "issuer has invalid token URL",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(brokenTokenURLServer))(h))
					return nil
				}
			},
			issuer:   brokenTokenURLServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + brokenTokenURLServer.URL + `"`},
			wantErr:  `discovered token URL from issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name: "issuer has insecure token URL",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(insecureTokenURLServer))(h))
					return nil
				}
			},
			issuer:   insecureTokenURLServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + insecureTokenURLServer.URL + `"`},
			wantErr:  `discovered token URL from issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name: "issuer has invalid authorize URL",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(brokenAuthURLServer))(h))
					return nil
				}
			},
			issuer:   brokenAuthURLServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + brokenAuthURLServer.URL + `"`},
			wantErr:  `discovered authorize URL from issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name: "issuer has insecure authorize URL",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(insecureAuthURLServer))(h))
					return nil
				}
			},
			issuer:   insecureAuthURLServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + insecureAuthURLServer.URL + `"`},
			wantErr:  `discovered authorize URL from issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name: "listen failure and non-tty stdin",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					h.listen = func(net string, addr string) (net.Listener, error) {
						assert.Equal(t, "tcp", net)
						assert.Equal(t, "localhost:0", addr)
						return nil, fmt.Errorf("some listen error")
					}
					h.isTTY = func(fd int) bool {
						assert.Equal(t, fd, syscall.Stdin)
						return false
					}
					return nil
				}
			},
			issuer: successServer.URL,
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"msg"="could not open callback listener" "error"="some listen error"`,
			},
			wantErr: "login failed: must have either a localhost listener or stdin must be a TTY",
		},
		{
			name: "listening disabled and manual prompt fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(formPostSuccessServer))(h))
					require.NoError(t, WithSkipListen()(h))
					h.isTTY = func(fd int) bool { return true }
					h.openURL = func(authorizeURL string) error {
						parsed, err := url.Parse(authorizeURL)
						require.NoError(t, err)
						require.Equal(t, "http://127.0.0.1:0/callback", parsed.Query().Get("redirect_uri"))
						require.Equal(t, "form_post", parsed.Query().Get("response_mode"))
						return fmt.Errorf("some browser open error")
					}
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						return "", fmt.Errorf("some prompt error")
					}
					return nil
				}
			},
			issuer: formPostSuccessServer.URL,
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + formPostSuccessServer.URL + `"`,
				`"msg"="could not open browser" "error"="some browser open error"`,
			},
			wantErr: "error handling callback: failed to prompt for manual authorization code: some prompt error",
		},
		{
			name: "listen success and manual prompt succeeds",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(formPostSuccessServer))(h))
					h.listen = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("some listen error") }
					h.isTTY = func(fd int) bool { return true }
					h.openURL = func(authorizeURL string) error {
						parsed, err := url.Parse(authorizeURL)
						require.NoError(t, err)
						require.Equal(t, "http://127.0.0.1:0/callback", parsed.Query().Get("redirect_uri"))
						require.Equal(t, "form_post", parsed.Query().Get("response_mode"))
						return nil
					}
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						return "", fmt.Errorf("some prompt error")
					}
					return nil
				}
			},
			issuer: formPostSuccessServer.URL,
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + formPostSuccessServer.URL + `"`,
				`"msg"="could not open callback listener" "error"="some listen error"`,
			},
			wantErr: "error handling callback: failed to prompt for manual authorization code: some prompt error",
		},
		{
			name: "timeout waiting for callback",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))

					ctx, cancel := context.WithCancel(h.ctx)
					h.ctx = ctx

					h.openURL = func(_ string) error {
						cancel()
						return nil
					}
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  "timed out waiting for token callback: context canceled",
		},
		{
			name: "callback returns error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					h.openURL = func(_ string) error {
						go func() {
							h.callbacks <- callbackResult{err: fmt.Errorf("some callback error")}
						}()
						return nil
					}
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  "error handling callback: some callback error",
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

					client := newClientForServer(successServer)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

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
			wantLogs:  []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantToken: &testToken,
		},
		{
			name:     "callback returns success with request_mode=form_post",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:      formPostSuccessServer.URL,
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

					client := newClientForServer(formPostSuccessServer)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

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
							"response_mode":         []string{"form_post"},
							"scope":                 []string{"test-scope"},
							"nonce":                 []string{"test-nonce"},
							"state":                 []string{"test-state"},
							"access_type":           []string{"offline"},
							"client_id":             []string{"test-client-id"},
						}, actualParams)

						parsedActualURL.RawQuery = ""
						require.Equal(t, formPostSuccessServer.URL+"/authorize", parsedActualURL.String())

						go func() {
							h.callbacks <- callbackResult{token: &testToken}
						}()
						return nil
					}
					return nil
				}
			},
			issuer:    formPostSuccessServer.URL,
			wantLogs:  []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + formPostSuccessServer.URL + "\""},
			wantToken: &testToken,
		},
		{
			name:     "upstream name and type are included in authorize request if upstream name is provided",
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
					require.NoError(t, WithUpstreamIdentityProvider("some-upstream-name", "oidc")(h))

					client := newClientForServer(successServer)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

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
							"pinniped_idp_name":     []string{"some-upstream-name"},
							"pinniped_idp_type":     []string{"oidc"},
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
			wantLogs:  []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantToken: &testToken,
		},
		{
			name:     "ldap login when prompting for username returns an error",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "", errors.New("some prompt error")
					}
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  "error prompting for username: some prompt error",
		},
		{
			name:     "ldap login when prompting for password returns an error",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)
					h.promptForSecret = func(_ string) (string, error) { return "", errors.New("some prompt error") }
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  "error prompting for password: some prompt error",
		},
		{
			name:     "ldap login when there is a problem with parsing the authorize URL",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)

					client := newClientForServer(successServer)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							type providerJSON struct {
								Issuer   string `json:"issuer"`
								AuthURL  string `json:"authorization_endpoint"`
								TokenURL string `json:"token_endpoint"`
								JWKSURL  string `json:"jwks_uri"`
							}
							jsonResponseBody, err := json.Marshal(&providerJSON{
								Issuer:   successServer.URL,
								AuthURL:  "%", // this is not a legal URL!
								TokenURL: successServer.URL + "/token",
								JWKSURL:  successServer.URL + "/keys",
							})
							require.NoError(t, err)
							return &http.Response{
								StatusCode: http.StatusOK,
								Header:     http.Header{"content-type": []string{"application/json"}},
								Body:       io.NopCloser(strings.NewReader(string(jsonResponseBody))),
							}, nil
						default:
							require.FailNow(t, fmt.Sprintf("saw unexpected http call from the CLI: %s", req.URL.String()))
							return nil, nil
						}
					})
					require.NoError(t, WithClient(client)(h))

					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `discovered authorize URL from issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name:     "ldap login when there is an error calling the authorization endpoint",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, nil, errors.New("some error fetching authorize endpoint"))
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `authorization response error: Get "https://` + successServer.Listener.Addr().String() +
				`/authorize?access_type=offline&client_id=test-client-id&code_challenge=VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g&code_challenge_method=S256&nonce=test-nonce&pinniped_idp_name=some-upstream-name&pinniped_idp_type=ldap&redirect_uri=http%3A%2F%2F127.0.0.1%3A0%2Fcallback&response_type=code&scope=test-scope&state=test-state": some error fetching authorize endpoint`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint returns something other than a redirect",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"}, nil)
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `error getting authorization: expected to be redirected, but response status was 502 Bad Gateway`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint redirect has an error and error description",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{
						StatusCode: http.StatusFound,
						Header: http.Header{"Location": []string{
							"http://127.0.0.1:0/callback?error=access_denied&error_description=optional-error-description&state=test-state",
						}},
					}, nil)
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `login failed with code "access_denied": optional-error-description`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint redirects us to a different server",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{
						StatusCode: http.StatusFound,
						Header: http.Header{"Location": []string{
							"http://other-server.example.com/callback?code=foo&state=test-state",
						}},
					}, nil)
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `error getting authorization: redirected to the wrong location: http://other-server.example.com/callback?code=foo&state=test-state`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint redirect has an error but no error description",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{
						StatusCode: http.StatusFound,
						Header: http.Header{"Location": []string{
							"http://127.0.0.1:0/callback?error=access_denied&state=test-state",
						}},
					}, nil)
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `login failed with code "access_denied"`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint redirect has the wrong state value",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{
						StatusCode: http.StatusFound,
						Header:     http.Header{"Location": []string{"http://127.0.0.1:0/callback?code=foo&state=wrong-state"}},
					}, nil)
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  `missing or invalid state parameter in authorization response: http://127.0.0.1:0/callback?code=foo&state=wrong-state`,
		},
		{
			name:     "ldap login when there is an error exchanging the authcode or validating the tokens",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"
					_ = defaultLDAPTestOpts(t, h, &http.Response{
						StatusCode: http.StatusFound,
						Header: http.Header{"Location": []string{
							fmt.Sprintf("http://127.0.0.1:0/callback?code=%s&state=test-state", fakeAuthCode),
						}},
					}, nil)
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(
								gomock.Any(), fakeAuthCode, pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), "http://127.0.0.1:0/callback").
							Return(nil, errors.New("some authcode exchange or token validation error"))
						return mock
					}
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr:  "error during authorization code exchange: some authcode exchange or token validation error",
		},
		{
			name:     "successful ldap login with prompts for username and password",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(
								gomock.Any(), fakeAuthCode, pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), "http://127.0.0.1:0/callback").
							Return(&testToken, nil)
						return mock
					}

					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.getEnv = func(_ string) string {
						return "" // asking for any env var returns empty as if it were unset
					}
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "some-upstream-username", nil
					}
					h.promptForSecret = func(promptLabel string) (string, error) {
						require.Equal(t, "Password: ", promptLabel)
						return "some-upstream-password", nil
					}

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
					require.NoError(t, WithCLISendingCredentials()(h))
					require.NoError(t, WithUpstreamIdentityProvider("some-upstream-name", "ldap")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := newClientForServer(successServer)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
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
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"some-upstream-name"},
								"pinniped_idp_type":     []string{"ldap"},
							}, req.URL.Query())
							return &http.Response{
								StatusCode: http.StatusFound,
								Header: http.Header{"Location": []string{
									fmt.Sprintf("http://127.0.0.1:0/callback?code=%s&state=test-state", fakeAuthCode),
								}},
							}, nil
						default:
							// Note that "/token" requests should not be made. They are mocked by mocking calls to ExchangeAuthcodeAndValidateTokens().
							require.FailNow(t, fmt.Sprintf("saw unexpected http call from the CLI: %s", req.URL.String()))
							return nil, nil
						}
					})
					require.NoError(t, WithClient(client)(h))
					return nil
				}
			},
			issuer:    successServer.URL,
			wantLogs:  []string{"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantToken: &testToken,
		},
		{
			name:     "successful ldap login with env vars for username and password",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(
								gomock.Any(), fakeAuthCode, pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), "http://127.0.0.1:0/callback").
							Return(&testToken, nil)
						return mock
					}

					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.getEnv = func(key string) string {
						switch key {
						case "PINNIPED_USERNAME":
							return "some-upstream-username"
						case "PINNIPED_PASSWORD":
							return "some-upstream-password"
						default:
							return "" // all other env vars are treated as if they are unset
						}
					}
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}
					h.promptForSecret = func(promptLabel string) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}

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
					require.NoError(t, WithCLISendingCredentials()(h))
					require.NoError(t, WithUpstreamIdentityProvider("some-upstream-name", "ldap")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := newClientForServer(successServer)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
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
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"some-upstream-name"},
								"pinniped_idp_type":     []string{"ldap"},
							}, req.URL.Query())
							return &http.Response{
								StatusCode: http.StatusFound,
								Header: http.Header{"Location": []string{
									fmt.Sprintf("http://127.0.0.1:0/callback?code=%s&state=test-state", fakeAuthCode),
								}},
							}, nil
						default:
							// Note that "/token" requests should not be made. They are mocked by mocking calls to ExchangeAuthcodeAndValidateTokens().
							require.FailNow(t, fmt.Sprintf("saw unexpected http call from the CLI: %s", req.URL.String()))
							return nil, nil
						}
					})
					require.NoError(t, WithClient(client)(h))
					return nil
				}
			},
			issuer: successServer.URL,
			wantLogs: []string{
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Read username from environment variable\"  \"name\"=\"PINNIPED_USERNAME\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Read password from environment variable\"  \"name\"=\"PINNIPED_PASSWORD\"",
			},
			wantToken: &testToken,
		},
		{
			name:     "successful ldap login with env vars for username and password, http.StatusSeeOther redirect",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(
								gomock.Any(), fakeAuthCode, pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), "http://127.0.0.1:0/callback").
							Return(&testToken, nil)
						return mock
					}

					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.getEnv = func(key string) string {
						switch key {
						case "PINNIPED_USERNAME":
							return "some-upstream-username"
						case "PINNIPED_PASSWORD":
							return "some-upstream-password"
						default:
							return "" // all other env vars are treated as if they are unset
						}
					}
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}
					h.promptForSecret = func(promptLabel string) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}

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
					require.NoError(t, WithCLISendingCredentials()(h))
					require.NoError(t, WithUpstreamIdentityProvider("some-upstream-name", "ldap")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := newClientForServer(successServer)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
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
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"some-upstream-name"},
								"pinniped_idp_type":     []string{"ldap"},
							}, req.URL.Query())
							return &http.Response{
								StatusCode: http.StatusSeeOther,
								Header: http.Header{"Location": []string{
									fmt.Sprintf("http://127.0.0.1:0/callback?code=%s&state=test-state", fakeAuthCode),
								}},
							}, nil
						default:
							// Note that "/token" requests should not be made. They are mocked by mocking calls to ExchangeAuthcodeAndValidateTokens().
							require.FailNow(t, fmt.Sprintf("saw unexpected http call from the CLI: %s", req.URL.String()))
							return nil, nil
						}
					})
					require.NoError(t, WithClient(client)(h))
					return nil
				}
			},
			issuer: successServer.URL,
			wantLogs: []string{
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Read username from environment variable\"  \"name\"=\"PINNIPED_USERNAME\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Read password from environment variable\"  \"name\"=\"PINNIPED_PASSWORD\"",
			},
			wantToken: &testToken,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but discovery fails",
			clientID: "test-client-id",
			issuer:   errorServer.URL,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      errorServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(errorServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"cluster-1234\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + errorServer.URL + "\""},
			wantErr: fmt.Sprintf("failed to exchange token: could not perform OIDC discovery for %q: 500 Internal Server Error: some discovery error\n", errorServer.URL),
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token URL is insecure",
			issuer:   insecureTokenURLServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      insecureTokenURLServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(insecureTokenURLServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"cluster-1234\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + insecureTokenURLServer.URL + "\""},
			wantErr: `failed to exchange token: discovered token URL from issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token URL is invalid",
			issuer:   brokenTokenURLServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      brokenTokenURLServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(brokenTokenURLServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"cluster-1234\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + brokenTokenURLServer.URL + "\""},
			wantErr: `failed to exchange token: discovered token URL from issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request fails",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-http-response")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-http-response\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: fmt.Sprintf(`failed to exchange token: Post "%s/token": failed to parse Location header "%%": parse "%%": invalid URL escape "%%"`, successServer.URL),
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns non-200",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-http-400")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-http-400\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: unexpected HTTP response status 400`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns invalid content-type header",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-content-type")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-content-type\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: failed to decode content-type header: mime: invalid media parameter`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns wrong content-type",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-wrong-content-type")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-wrong-content-type\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: unexpected HTTP response content type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns invalid JSON",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-json")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-json\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: failed to decode response: unexpected EOF`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns invalid token_type",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-tokentype")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-tokentype\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: got unexpected token_type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns invalid issued_token_type",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-issuedtokentype")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-issuedtokentype\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: got unexpected issued_token_type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, but token exchange request returns invalid JWT",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-jwt")(h))
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience-produce-invalid-jwt\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantErr: `failed to exchange token: received invalid JWT: oidc: malformed jwt: oidc: malformed jwt, expected 3 parts got 1`,
		},
		{
			name:     "with requested audience, session cache hit with valid token, and token exchange request succeeds",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &testToken}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(newClientForServer(successServer))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience")(h))

					h.validateIDToken = func(ctx context.Context, provider *oidc.Provider, audience string, token string) (*oidc.IDToken, error) {
						require.Equal(t, "test-audience", audience)
						require.Equal(t, "test-id-token-with-requested-audience", token)
						return &oidc.IDToken{Expiry: testExchangedToken.IDToken.Expiry.Time}, nil
					}
					return nil
				}
			},
			wantLogs: []string{"\"level\"=4 \"msg\"=\"Pinniped: Found unexpired cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\""},
			wantToken: &testExchangedToken,
		},
		{
			name:     "with requested audience, session cache hit with valid refresh token, and token exchange request succeeds",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(newClientForServer(successServer))(h))

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

					h.getProvider = func(config *oauth2.Config, provider *oidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateTokenAndMergeWithUserInfo(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce(""), true, false).
							Return(&testToken, nil)
						mock.EXPECT().
							PerformRefresh(gomock.Any(), testToken.RefreshToken.Token).
							DoAndReturn(func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
								// Call the real production code to perform a refresh.
								return upstreamoidc.New(config, provider, client).PerformRefresh(ctx, refreshToken)
							})
						return mock
					}

					require.NoError(t, WithRequestAudience("test-audience")(h))

					h.validateIDToken = func(ctx context.Context, provider *oidc.Provider, audience string, token string) (*oidc.IDToken, error) {
						require.Equal(t, "test-audience", audience)
						require.Equal(t, "test-id-token-with-requested-audience", token)
						return &oidc.IDToken{Expiry: testExchangedToken.IDToken.Expiry.Time}, nil
					}
					return nil
				}
			},
			wantLogs: []string{
				"\"level\"=4 \"msg\"=\"Pinniped: Performing OIDC discovery\"  \"issuer\"=\"" + successServer.URL + "\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Refreshing cached token.\"",
				"\"level\"=4 \"msg\"=\"Pinniped: Performing RFC8693 token exchange\"  \"requestedAudience\"=\"test-audience\"",
			},
			wantToken: &testExchangedToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			testLogger := testlogger.NewLegacy(t) //nolint:staticcheck  // old test with lots of log statements
			klog.SetLogger(testLogger.Logger)

			tok, err := Login(tt.issuer, tt.clientID,
				WithContext(context.Background()),
				WithListenPort(0),
				WithScopes([]string{"test-scope"}),
				WithSkipBrowserOpen(),
				tt.opt(t),
				WithLogger(testLogger.Logger),
			)
			testLogger.Expect(tt.wantLogs)
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

func TestHandlePasteCallback(t *testing.T) {
	const testRedirectURI = "http://127.0.0.1:12324/callback"

	tests := []struct {
		name         string
		opt          func(t *testing.T) Option
		wantCallback *callbackResult
	}{
		{
			name: "no stdin available",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.isTTY = func(fd int) bool {
						require.Equal(t, syscall.Stdin, fd)
						return false
					}
					h.useFormPost = true
					return nil
				}
			},
		},
		{
			name: "no form_post mode available",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.isTTY = func(fd int) bool { return true }
					h.useFormPost = false
					return nil
				}
			},
		},
		{
			name: "prompt fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.isTTY = func(fd int) bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						assert.Equal(t, "    Optionally, paste your authorization code: ", promptLabel)
						return "", fmt.Errorf("some prompt error")
					}
					return nil
				}
			},
			wantCallback: &callbackResult{
				err: fmt.Errorf("failed to prompt for manual authorization code: some prompt error"),
			},
		},
		{
			name: "redeeming code fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.isTTY = func(fd int) bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						return "invalid", nil
					}
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "invalid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(nil, fmt.Errorf("some exchange error"))
						return mock
					}
					return nil
				}
			},
			wantCallback: &callbackResult{
				err: fmt.Errorf("some exchange error"),
			},
		},
		{
			name: "success",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.isTTY = func(fd int) bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string) (string, error) {
						return "valid", nil
					}
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
						return mock
					}
					return nil
				}
			},
			wantCallback: &callbackResult{
				token: &oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
			}
			if tt.opt != nil {
				require.NoError(t, tt.opt(t)(h))
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			var buf bytes.Buffer
			h.promptForWebLogin(ctx, "https://test-authorize-url/", &buf)
			require.Equal(t,
				"Log in by visiting this link:\n\n    https://test-authorize-url/\n\n",
				buf.String(),
			)

			if tt.wantCallback != nil {
				select {
				case <-time.After(1 * time.Second):
					require.Fail(t, "timed out waiting to receive from callbacks channel")
				case result := <-h.callbacks:
					require.Equal(t, *tt.wantCallback, result)
				}
			}
		})
	}
}

func TestHandleAuthCodeCallback(t *testing.T) {
	const testRedirectURI = "http://127.0.0.1:12324/callback"

	withFormPostMode := func(t *testing.T) Option {
		return func(h *handlerState) error {
			h.useFormPost = true
			return nil
		}
	}
	tests := []struct {
		name    string
		method  string
		query   string
		body    []byte
		headers http.Header
		opt     func(t *testing.T) Option

		wantErr         string
		wantHTTPStatus  int
		wantNoCallbacks bool
		wantHeaders     http.Header
	}{
		{
			name:            "wrong method returns an error but keeps listening",
			method:          http.MethodPost,
			query:           "",
			wantNoCallbacks: true,
			wantHeaders:     map[string][]string{},
			wantHTTPStatus:  http.StatusMethodNotAllowed,
		},
		{
			name:            "wrong method for form_post returns an error but keeps listening",
			method:          http.MethodGet,
			query:           "",
			opt:             withFormPostMode,
			wantNoCallbacks: true,
			wantHeaders:     map[string][]string{},
			wantHTTPStatus:  http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid form for form_post",
			method:         http.MethodPost,
			query:          "",
			headers:        map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			body:           []byte(`%`),
			opt:            withFormPostMode,
			wantErr:        `invalid form: invalid URL escape "%"`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid state",
			query:          "state=invalid",
			wantErr:        "missing or invalid state parameter",
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusForbidden,
		},
		{
			name:           "error code from provider",
			query:          "state=test-state&error=some_error",
			wantErr:        `login failed with code "some_error"`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "error code with a description from provider",
			query:          "state=test-state&error=some_error&error_description=optional%20error%20description",
			wantErr:        `login failed with code "some_error": optional error description`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "in form post mode, invalid issuer url config during CORS preflight request returns an error",
			method:         http.MethodOptions,
			query:          "",
			headers:        map[string][]string{"Origin": {"https://some-origin.com"}},
			wantErr:        `invalid issuer url: parse "://bad-url": missing protocol scheme`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusInternalServerError,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.issuer = "://bad-url"
					return nil
				}
			},
		},
		{
			name:           "in form post mode, invalid issuer url config during POST request returns an error",
			method:         http.MethodPost,
			query:          "",
			headers:        map[string][]string{"Origin": {"https://some-origin.com"}},
			wantErr:        `invalid issuer url: parse "://bad-url": missing protocol scheme`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusInternalServerError,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.issuer = "://bad-url"
					return nil
				}
			},
		},
		{
			name:            "in form post mode, options request is missing origin header results in 400 and keeps listener running",
			method:          http.MethodOptions,
			query:           "",
			opt:             withFormPostMode,
			wantNoCallbacks: true,
			wantHeaders:     map[string][]string{},
			wantHTTPStatus:  http.StatusBadRequest,
		},
		{
			name:            "in form post mode, valid CORS request responds with 402 and CORS headers and keeps listener running",
			method:          http.MethodOptions,
			query:           "",
			headers:         map[string][]string{"Origin": {"https://some-origin.com"}},
			wantNoCallbacks: true,
			wantHTTPStatus:  http.StatusNoContent,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Credentials":     {"false"},
				"Access-Control-Allow-Methods":         {"POST, OPTIONS"},
				"Access-Control-Allow-Origin":          {"https://valid-issuer.com"},
				"Vary":                                 {"*"},
				"Access-Control-Allow-Private-Network": {"true"},
			},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.issuer = "https://valid-issuer.com/with/some/path"
					return nil
				}
			},
		},
		{
			name:   "in form post mode, valid CORS request with Access-Control-Request-Headers responds with 402 and CORS headers including Access-Control-Allow-Headers and keeps listener running",
			method: http.MethodOptions,
			query:  "",
			headers: map[string][]string{
				"Origin":                         {"https://some-origin.com"},
				"Access-Control-Request-Headers": {"header1, header2, header3"},
			},
			wantNoCallbacks: true,
			wantHTTPStatus:  http.StatusNoContent,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Credentials":     {"false"},
				"Access-Control-Allow-Methods":         {"POST, OPTIONS"},
				"Access-Control-Allow-Origin":          {"https://valid-issuer.com"},
				"Vary":                                 {"*"},
				"Access-Control-Allow-Private-Network": {"true"},
				"Access-Control-Allow-Headers":         {"header1, header2, header3"},
			},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.issuer = "https://valid-issuer.com/with/some/path"
					return nil
				}
			},
		},
		{
			name:           "invalid code",
			query:          "state=test-state&code=invalid",
			wantErr:        "could not complete code exchange: some exchange error",
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusBadRequest,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "invalid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(nil, fmt.Errorf("some exchange error"))
						return mock
					}
					return nil
				}
			},
		},
		{
			name:           "valid",
			query:          "state=test-state&code=valid",
			wantHTTPStatus: http.StatusOK,
			wantHeaders:    map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
						return mock
					}
					return nil
				}
			},
		},
		{
			name:    "valid form_post",
			method:  http.MethodPost,
			headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			body:    []byte(`state=test-state&code=valid`),
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
				"Content-Type":                {"text/plain; charset=utf-8"},
			},
			wantHTTPStatus: http.StatusOK,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
						return mock
					}
					return nil
				}
			},
		},
		{
			name:   "valid form_post made with the same origin headers that would be used by a Javascript fetch client using mode=cors",
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/x-www-form-urlencoded"},
				"Origin":       {"https://some-origin.com"},
			},
			body: []byte(`state=test-state&code=valid`),
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
				"Content-Type":                {"text/plain; charset=utf-8"},
			},
			wantHTTPStatus: http.StatusOK,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.useFormPost = true
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *oidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
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
			t.Parallel()

			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
				logger:    plog.Logr(), //nolint:staticcheck  // old test with no log assertions
				issuer:    "https://valid-issuer.com/with/some/path",
			}
			if tt.opt != nil {
				require.NoError(t, tt.opt(t)(h))
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			resp := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, "GET", "/test-callback", bytes.NewBuffer(tt.body))
			require.NoError(t, err)
			req.URL.RawQuery = tt.query
			if tt.method != "" {
				req.Method = tt.method
			}
			if tt.headers != nil {
				req.Header = tt.headers
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
				require.Equal(t, tt.wantHTTPStatus, resp.Code)
			}

			if tt.wantHeaders != nil {
				require.Equal(t, tt.wantHeaders, resp.Header())
			}

			gotCallback := false
			select {
			case <-time.After(1 * time.Second):
				if !tt.wantNoCallbacks {
					require.Fail(t, "timed out waiting to receive from callbacks channel")
				}
			case result := <-h.callbacks:
				if tt.wantErr != "" {
					require.EqualError(t, result.err, tt.wantErr)
					return
				}
				require.NoError(t, result.err)
				require.NotNil(t, result.token)
				require.Equal(t, result.token.IDToken.Token, "test-id-token")
				gotCallback = true
			}
			require.Equal(t, tt.wantNoCallbacks, !gotCallback)
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
