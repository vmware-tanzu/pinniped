// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
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
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/endpoints/discovery"
	federationdomainoidc "go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/mocks/mockupstreamoidcidentityprovider"
	"go.pinniped.dev/internal/net/phttp"
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

func buildHTTPClientForPEM(pemData []byte) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return phttp.Default(pool)
}

func TestLogin(t *testing.T) { //nolint:gocyclo
	fakeUniqueTime := time.Now().Add(6 * time.Minute).Add(6 * time.Second)

	distantFutureTime := time.Date(2065, 10, 12, 13, 14, 15, 16, time.UTC)

	testCodeChallenge := testutil.SHA256("test-pkce")

	testToken := oidctypes.Token{
		AccessToken:  &oidctypes.AccessToken{Token: "test-access-token", Expiry: metav1.NewTime(distantFutureTime.Add(1 * time.Minute))},
		RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
		IDToken:      &oidctypes.IDToken{Token: "test-id-token", Expiry: metav1.NewTime(distantFutureTime.Add(2 * time.Minute))},
	}

	testExchangedToken := oidctypes.Token{
		IDToken: &oidctypes.IDToken{Token: "test-id-token-with-requested-audience", Expiry: metav1.NewTime(distantFutureTime.Add(3 * time.Minute))},
	}

	// Start a test server that returns 500 errors.
	errorServer, errorServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "some discovery error", http.StatusInternalServerError)
	}), nil)

	// Start a test server that returns discovery data with a broken response_modes_supported value.
	brokenResponseModeMux := http.NewServeMux()
	brokenResponseModeServer, brokenResponseModeServerCA := tlsserver.TestServerIPv4(t, brokenResponseModeMux, nil)
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
	brokenTokenURLServer, brokenTokenURLServerCA := tlsserver.TestServerIPv4(t, brokenTokenURLMux, nil)
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
	insecureTokenURLServer, insecureTokenURLServerCA := tlsserver.TestServerIPv4(t, insecureTokenURLMux, nil)
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
	brokenAuthURLServer, brokenAuthURLServerCA := tlsserver.TestServerIPv4(t, brokenAuthURLMux, nil)
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
	insecureAuthURLServer, insecureAuthURLServerCA := tlsserver.TestServerIPv4(t, insecureAuthURLMux, nil)
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

	// Start a test server that returns IDP discovery at some other location
	emptyIDPDiscoveryMux := http.NewServeMux()
	emptyIDPDiscoveryServer, emptyIDPDiscoveryServerCA := tlsserver.TestServerIPv4(t, emptyIDPDiscoveryMux, nil)
	emptyIDPDiscoveryMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&struct {
			Issuer                 string                                                `json:"issuer"`
			AuthURL                string                                                `json:"authorization_endpoint"`
			TokenURL               string                                                `json:"token_endpoint"`
			JWKSURL                string                                                `json:"jwks_uri"`
			ResponseModesSupported []string                                              `json:"response_modes_supported,omitempty"`
			SupervisorDiscovery    idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
		}{
			Issuer:                 emptyIDPDiscoveryServer.URL,
			AuthURL:                emptyIDPDiscoveryServer.URL + "/authorize",
			TokenURL:               emptyIDPDiscoveryServer.URL + "/token",
			JWKSURL:                emptyIDPDiscoveryServer.URL + "/keys",
			ResponseModesSupported: []string{},
			SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
				PinnipedIDPsEndpoint: "https://example.com" + federationdomainoidc.PinnipedIDPsPathV1Alpha1,
			},
		})
	})

	// Start a test server that has invalid IDP discovery
	invalidIDPDiscoveryMux := http.NewServeMux()
	invalidIDPDiscoveryServer, invalidIDPDiscoveryServerCA := tlsserver.TestServerIPv4(t, invalidIDPDiscoveryMux, nil)
	invalidIDPDiscoveryMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&struct {
			Issuer                 string                                                `json:"issuer"`
			AuthURL                string                                                `json:"authorization_endpoint"`
			TokenURL               string                                                `json:"token_endpoint"`
			JWKSURL                string                                                `json:"jwks_uri"`
			ResponseModesSupported []string                                              `json:"response_modes_supported,omitempty"`
			SupervisorDiscovery    idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
		}{
			Issuer:                 invalidIDPDiscoveryServer.URL,
			AuthURL:                invalidIDPDiscoveryServer.URL + "/authorize",
			TokenURL:               invalidIDPDiscoveryServer.URL + "/token",
			JWKSURL:                invalidIDPDiscoveryServer.URL + "/keys",
			ResponseModesSupported: []string{},
			SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
				PinnipedIDPsEndpoint: invalidIDPDiscoveryServer.URL + federationdomainoidc.PinnipedIDPsPathV1Alpha1,
			},
		})
	})
	invalidIDPDiscoveryMux.HandleFunc(federationdomainoidc.PinnipedIDPsPathV1Alpha1, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = fmt.Fprint(w, "not real json")
	})

	discoveryHandler := func(server *httptest.Server, responseModes []string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&struct {
				Issuer                 string                                                `json:"issuer"`
				AuthURL                string                                                `json:"authorization_endpoint"`
				TokenURL               string                                                `json:"token_endpoint"`
				JWKSURL                string                                                `json:"jwks_uri"`
				ResponseModesSupported []string                                              `json:"response_modes_supported,omitempty"`
				SupervisorDiscovery    idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
			}{
				Issuer:                 server.URL,
				AuthURL:                server.URL + "/authorize",
				TokenURL:               server.URL + "/token",
				JWKSURL:                server.URL + "/keys",
				ResponseModesSupported: responseModes,
				SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
					PinnipedIDPsEndpoint: server.URL + federationdomainoidc.PinnipedIDPsPathV1Alpha1,
				},
			})
		}
	}

	idpDiscoveryHandler := func(server *httptest.Server) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(idpdiscoveryv1alpha1.IDPDiscoveryResponse{
				PinnipedIDPs: []idpdiscoveryv1alpha1.PinnipedIDP{
					{
						Name: "upstream-idp-name-with-cli-password-flow-first",
						Type: "upstream-idp-type-with-cli-password-flow-first",
						Flows: []idpdiscoveryv1alpha1.IDPFlow{
							idpdiscoveryv1alpha1.IDPFlowCLIPassword,
							idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode,
						},
					},
					{
						Name: "upstream-idp-name-with-browser-authcode-flow-first",
						Type: "upstream-idp-type-with-browser-authcode-flow-first",
						Flows: []idpdiscoveryv1alpha1.IDPFlow{
							idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode,
							idpdiscoveryv1alpha1.IDPFlowCLIPassword,
						},
					},
				},
				PinnipedSupportedIDPTypes: []idpdiscoveryv1alpha1.PinnipedSupportedIDPType{
					{Type: "upstream-idp-type-with-cli-password-flow-first"},
					{Type: "upstream-idp-type-with-browser-authcode-flow-first"},
				},
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
	successServer, successServerCA := tlsserver.TestServerIPv4(t, providerMux, nil)
	providerMux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(successServer, nil))
	providerMux.HandleFunc(federationdomainoidc.PinnipedIDPsPathV1Alpha1, idpDiscoveryHandler(successServer))
	providerMux.HandleFunc("/token", tokenHandler)

	// Start a test server that returns a real discovery document and answers refresh requests, _and_ supports form_mode=post.
	formPostProviderMux := http.NewServeMux()
	formPostSuccessServer, formPostSuccessServerCA := tlsserver.TestServerIPv4(t, formPostProviderMux, nil)
	formPostProviderMux.HandleFunc("/.well-known/openid-configuration", discoveryHandler(formPostSuccessServer, []string{"query", "form_post"}))
	formPostProviderMux.HandleFunc(federationdomainoidc.PinnipedIDPsPathV1Alpha1, idpDiscoveryHandler(formPostSuccessServer))
	formPostProviderMux.HandleFunc("/token", tokenHandler)

	// TODO: Use a test server without federationdomainoidc.PinnipedIDPsPathV1Alpha1 (e.g. a non-Supervisor server)

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
		h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
			return "some-upstream-username", nil
		}
		h.promptForSecret = func(_ string, _ io.Writer) (string, error) { return "some-upstream-password", nil }

		cache := &mockSessionCache{t: t, getReturnsToken: nil}
		cacheKey := SessionCacheKey{
			Issuer:               successServer.URL,
			ClientID:             "test-client-id",
			Scopes:               []string{"test-scope"},
			RedirectURI:          "http://localhost:0/callback",
			UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
		}
		t.Cleanup(func() {
			require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
		})
		require.NoError(t, WithSessionCache(cache)(h))
		require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))
		require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "upstream-idp-type-with-cli-password-flow-first")(h))
		require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

		require.NoError(t, WithClient(&http.Client{
			Transport: roundtripper.Func(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
				case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
					return defaultDiscoveryResponse(req)
				case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
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
		name       string
		opt        func(t *testing.T) Option
		issuer     string
		clientID   string
		wantErr    string
		wantToken  *oidctypes.Token
		wantLogs   []string
		wantStdErr string
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
			name: "WithLoginFlow option and deprecated WithCLISendingCredentials option cannot be used together (with CLI flow selected)",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithCLISendingCredentials()(h)) // This is meant to call a deprecated function
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))
					return nil
				}
			},
			wantErr: "do not use deprecated option WithCLISendingCredentials when using option WithLoginFlow",
		},
		{
			name: "WithLoginFlow option and deprecated WithCLISendingCredentials option cannot be used together (with browser flow selected)",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithCLISendingCredentials()(h)) // This is meant to call a deprecated function
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode, "flowSource")(h))
					return nil
				}
			},
			wantErr: "do not use deprecated option WithCLISendingCredentials when using option WithLoginFlow",
		},
		{
			name: "WithLoginFlow option rejects a non-enum value",
			opt: func(t *testing.T) Option {
				return WithLoginFlow("this is not one of the enum values", "some-flow-source")
			},
			wantErr: "WithLoginFlow error: loginFlow 'this is not one of the enum values' from 'some-flow-source' must be 'cli_password' or 'browser_authcode'",
		},
		{
			name: "WithLoginFlow option will not accept empty string either",
			opt: func(t *testing.T) Option {
				return WithLoginFlow("", "other-flow-source")
			},
			wantErr: "WithLoginFlow error: loginFlow '' from 'other-flow-source' must be 'cli_password' or 'browser_authcode'",
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
			name:     "without request audience, session cache hit but ID token expired",
			issuer:   errorServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(errorServerCA))(h))
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Minute)), // less than Now() + minIDTokenValidity
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
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + errorServer.URL + `"`},
			wantErr:  `could not perform OIDC discovery for "` + errorServer.URL + `": 500 Internal Server Error: some discovery error` + "\n",
		},
		{
			name:     "without request audience, session cache hit with valid ID token",
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
					require.NoError(t, WithSessionCache(cache)(h))
					return nil
				}
			},
			wantLogs:  []string{`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="id_token"`},
			wantToken: &testToken,
		},
		{
			name: "discovery failure due to 500 error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(errorServerCA))(h))
					return nil
				}
			},
			issuer:   errorServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + errorServer.URL + `"`},
			wantErr:  fmt.Sprintf("could not perform OIDC discovery for %q: 500 Internal Server Error: some discovery error\n", errorServer.URL),
		},
		{
			name: "discovery failure due to invalid response_modes_supported",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(brokenResponseModeServerCA))(h))
					return nil
				}
			},
			issuer:   brokenResponseModeServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + brokenResponseModeServer.URL + `"`},
			wantErr:  fmt.Sprintf("could not decode response_modes_supported in OIDC discovery from %q: json: cannot unmarshal string into Go struct field .response_modes_supported of type []string", brokenResponseModeServer.URL),
		},
		{
			name:     "without request audience, session cache hit with expired ID token which is refreshable",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

					h.getProvider = func(config *oauth2.Config, provider *coreosoidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Minute)), // less than Now() + minIDTokenValidity
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
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached tokens."`,
			},
			wantToken: &testToken,
		},
		{
			name:     "session cache hit but refresh returns invalid token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

					h.getProvider = func(config *oauth2.Config, provider *coreosoidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Minute)), // less than Now() + minIDTokenValidity
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
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached tokens."`,
			},
			wantErr: "some validation error",
		},
		{
			name:     "session cache hit but refresh fails",
			issuer:   successServer.URL,
			clientID: "not-the-test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "expired-test-id-token",
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Minute)), // less than Now() + minIDTokenValidity
						},
						RefreshToken: &oidctypes.RefreshToken{Token: "test-refresh-token"},
					}}
					t.Cleanup(func() {
						require.Empty(t, cache.sawPutKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					h.cache = cache

					h.listen = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("some listen error") }
					h.stdinIsTTY = func() bool { return false }
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached tokens."`,
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(brokenTokenURLServerCA))(h))
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(insecureTokenURLServerCA))(h))
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(brokenAuthURLServerCA))(h))
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(insecureAuthURLServerCA))(h))
					return nil
				}
			},
			issuer:   insecureAuthURLServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + insecureAuthURLServer.URL + `"`},
			wantErr:  `discovered authorize URL from issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name: "issuer has Pinniped Supervisor's IDP discovery, but from another location",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(emptyIDPDiscoveryServerCA))(h))
					return nil
				}
			},
			issuer:   emptyIDPDiscoveryServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + emptyIDPDiscoveryServer.URL + `"`},
			wantErr:  fmt.Sprintf(`the Pinniped IDP discovery document must always be hosted by the issuer: %q`, emptyIDPDiscoveryServer.URL),
		},
		{
			name: "issuer has Pinniped Supervisor's IDP discovery, but it cannot be unmarshaled",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(invalidIDPDiscoveryServerCA))(h))
					return nil
				}
			},
			issuer:   invalidIDPDiscoveryServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + invalidIDPDiscoveryServer.URL + `"`},
			wantErr:  "unable to fetch the Pinniped IDP discovery document: could not parse response JSON: invalid character 'o' in literal null (expecting 'u')",
		},
		{
			name: "listen failure and non-tty stdin",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					h.listen = func(net string, addr string) (net.Listener, error) {
						assert.Equal(t, "tcp", net)
						assert.Equal(t, "localhost:0", addr)
						return nil, fmt.Errorf("some listen error")
					}
					h.stdinIsTTY = func() bool { return false }
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
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.stdinIsTTY = func() bool { return true }
					require.NoError(t, WithClient(buildHTTPClientForPEM(formPostSuccessServerCA))(h))
					require.NoError(t, WithSkipListen()(h))
					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(authorizeURL string) error {
						parsed, err := url.Parse(authorizeURL)
						require.NoError(t, err)
						require.Equal(t, "http://127.0.0.1:0/callback", parsed.Query().Get("redirect_uri"))
						require.Equal(t, "form_post", parsed.Query().Get("response_mode"))
						return fmt.Errorf("some browser open error")
					}
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
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
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A0%2Fcallback"+
					"&response_mode=form_post&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n[...]\n\n") +
				"$",
			wantErr: "error handling callback: failed to prompt for manual authorization code: some prompt error",
		},
		{
			name: "listening fails and manual prompt fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.stdinIsTTY = func() bool { return true }
					require.NoError(t, WithClient(buildHTTPClientForPEM(formPostSuccessServerCA))(h))
					h.listen = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("some listen error") }
					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(authorizeURL string) error {
						parsed, err := url.Parse(authorizeURL)
						require.NoError(t, err)
						require.Equal(t, "http://127.0.0.1:0/callback", parsed.Query().Get("redirect_uri"))
						require.Equal(t, "form_post", parsed.Query().Get("response_mode"))
						return nil
					}
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
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
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A0%2Fcallback"+
					"&response_mode=form_post&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n[...]\n\n") +
				"$",
			wantErr: "error handling callback: failed to prompt for manual authorization code: some prompt error",
		},
		{
			name: "timeout waiting for callback",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.stdinIsTTY = func() bool { return true }

					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

					ctx, cancel := context.WithCancel(h.ctx)
					h.ctx = ctx

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(_ string) error {
						cancel()
						return nil
					}
					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
			wantErr: "timed out waiting for token callback: context canceled",
		},
		{
			name: "callback returns error",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.stdinIsTTY = func() bool { return true }
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					h.skipBrowser = false // don't skip calling the following openURL func
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
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
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

					h.stdinIsTTY = func() bool { return true }

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

					client := buildHTTPClientForPEM(successServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							"code_challenge":        []string{testCodeChallenge},
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
			issuer:   successServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=test-client-id&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
			wantToken: &testToken,
		},
		{
			name:     "callback returns success, with skipPrintLoginURL and with opening the browser, did not show authorize URL on stderr",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					h.stdinIsTTY = func() bool { return true }
					h.skipPrintLoginURL = true

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

					client := buildHTTPClientForPEM(successServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							"code_challenge":        []string{testCodeChallenge},
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "", // does not show "Log in by visiting this link" with authorize URL
			wantToken:  &testToken,
		},
		{
			name:     "callback returns success, with skipPrintLoginURL but there was an error when opening the browser, did show authorize URL on stderr",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					h.stdinIsTTY = func() bool { return true }
					h.skipPrintLoginURL = true

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

					client := buildHTTPClientForPEM(successServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							"code_challenge":        []string{testCodeChallenge},
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
						return fmt.Errorf("some error while opening browser")
					}
					return nil
				}
			},
			issuer: successServer.URL,
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"msg"="could not open browser" "error"="some error while opening browser"`,
			},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=test-client-id&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
			wantToken: &testToken,
		},
		{
			name:     "callback returns success, with skipPrintLoginURL and with skipping the browser, did show authorize URL on stderr",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					h.stdinIsTTY = func() bool { return true }
					h.skipPrintLoginURL = true

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

					client := buildHTTPClientForPEM(successServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = true

					// Allow the login to finish so this test does not hang waiting for the callback,
					// and so we can check if the authorize URL was shown on stderr.
					// The openURL function will be skipped, so we can't put this code inside the
					// mock version of that function as we do for other tests in this file.
					go func() {
						h.callbacks <- callbackResult{token: &testToken}
					}()

					return nil
				}
			},
			issuer:   successServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=test-client-id&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
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

					h.stdinIsTTY = func() bool { return true }

					// Because response_mode=form_post, the Login function is going to prompt the user
					// to paste their authcode. This test needs to handle that prompt.
					h.promptForValue = func(ctx context.Context, promptLabel string, _ io.Writer) (string, error) {
						assert.Equal(t, "    Optionally, paste your authorization code: ", promptLabel)
						// This test does not want to simulate the user entering their authcode at the prompt,
						// nor does it want to simulate a prompt error, so this function should hang as if
						// we are waiting for user input. Otherwise, promptForWebLogin would be racing to
						// write the result of this function to the callback chan (versus this test trying
						// to write its own callbackResult to the same chan).
						// The context passed into this function should be cancelled by the caller when it
						// has received the authcode callback because the caller is no longer interested in
						// waiting for the prompt anymore at that point, so this function can finish when
						// the context is cancelled.
						<-ctx.Done()
						return "", errors.New("this error should be ignored by the caller because the context is already cancelled")
					}

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

					client := buildHTTPClientForPEM(formPostSuccessServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							"code_challenge":        []string{testCodeChallenge},
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
			issuer:   formPostSuccessServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + formPostSuccessServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=test-client-id&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_mode=form_post&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n[...]\n\n") +
				"$",
			wantToken: &testToken,
		},
		{
			// TODO: This test name says that "upstream type" is included in the session cache key but I don't see that below.
			name:     "upstream name and type are included in authorize request and session cache key if upstream name is provided",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }

					h.stdinIsTTY = func() bool { return true }

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-browser-authcode-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-browser-authcode-flow-first", "upstream-idp-type-with-browser-authcode-flow-first")(h))

					client := buildHTTPClientForPEM(successServerCA)
					client.Timeout = 10 * time.Second
					require.NoError(t, WithClient(client)(h))

					h.skipBrowser = false // don't skip calling the following openURL func
					h.openURL = func(actualURL string) error {
						parsedActualURL, err := url.Parse(actualURL)
						require.NoError(t, err)
						actualParams := parsedActualURL.Query()

						require.Contains(t, actualParams.Get("redirect_uri"), "http://127.0.0.1:")
						actualParams.Del("redirect_uri")

						require.Equal(t, url.Values{
							"code_challenge":        []string{testCodeChallenge},
							"code_challenge_method": []string{"S256"},
							"response_type":         []string{"code"},
							"scope":                 []string{"test-scope"},
							"nonce":                 []string{"test-nonce"},
							"state":                 []string{"test-state"},
							"access_type":           []string{"offline"},
							"client_id":             []string{"test-client-id"},
							"pinniped_idp_name":     []string{"upstream-idp-name-with-browser-authcode-flow-first"},
							"pinniped_idp_type":     []string{"upstream-idp-type-with-browser-authcode-flow-first"},
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
			issuer:   successServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^" +
				regexp.QuoteMeta("Log in by visiting this link:\n\n") +
				regexp.QuoteMeta("    https://127.0.0.1:") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("/authorize?access_type=offline&client_id=test-client-id&code_challenge="+testCodeChallenge+
					"&code_challenge_method=S256&nonce=test-nonce&pinniped_idp_name=upstream-idp-name-with-browser-authcode-flow-first&pinniped_idp_type=upstream-idp-type-with-browser-authcode-flow-first"+
					"&redirect_uri=http%3A%2F%2F127.0.0.1%3A") +
				"[0-9]+" + // random port
				regexp.QuoteMeta("%2Fcallback&response_type=code&scope=test-scope&state=test-state") +
				regexp.QuoteMeta("\n\n") +
				"$",
			wantToken: &testToken,
		},
		{
			name:     "ldap login when prompting for username returns an error",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "", errors.New("some prompt error")
					}
					return nil
				}
			},
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    "error prompting for username: some prompt error",
		},
		{
			name:     "ldap login when prompting for password returns an error",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)
					h.promptForSecret = func(_ string, _ io.Writer) (string, error) { return "", errors.New("some prompt error") }
					return nil
				}
			},
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    "error prompting for password: some prompt error",
		},
		{
			name:     "ldap login when there is a problem with parsing the authorize URL",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					_ = defaultLDAPTestOpts(t, h, nil, nil)

					client := buildHTTPClientForPEM(successServerCA)
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
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr: `authorization response error: Get "https://` + successServer.Listener.Addr().String() +
				`/authorize?access_type=offline&client_id=test-client-id&code_challenge=` + testCodeChallenge +
				`&code_challenge_method=S256&nonce=test-nonce&pinniped_idp_name=upstream-idp-name-with-cli-password-flow-first&` +
				`pinniped_idp_type=upstream-idp-type-with-cli-password-flow-first&redirect_uri=http%3A%2F%2F127.0.0.1%3A0%2Fcallback&response_type=code` +
				`&scope=test-scope&state=test-state": some error fetching authorize endpoint`,
		},
		{
			name:     "ldap login when the OIDC provider authorization endpoint returns something other than a redirect",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					return defaultLDAPTestOpts(t, h, &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"}, nil)
				}
			},
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    `error getting authorization: expected to be redirected, but response status was 502 Bad Gateway`,
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    `login failed with code "access_denied": optional-error-description`,
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    `error getting authorization: redirected to the wrong location: http://other-server.example.com/callback?code=foo&state=test-state`,
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    `login failed with code "access_denied"`,
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    `missing or invalid state parameter in authorization response: http://127.0.0.1:0/callback?code=foo&state=wrong-state`,
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
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantErr:    "could not complete authorization code exchange: some authcode exchange or token validation error",
		},
		{
			name:     "successful ldap login with prompts for username and password",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "some-upstream-username", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Password: ", promptLabel)
						return "some-upstream-password", nil
					}

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "upstream-idp-type-with-cli-password-flow-first")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
							require.Equal(t, url.Values{
								"code_challenge":        []string{testCodeChallenge},
								"code_challenge_method": []string{"S256"},
								"response_type":         []string{"code"},
								"scope":                 []string{"test-scope"},
								"nonce":                 []string{"test-nonce"},
								"state":                 []string{"test-state"},
								"access_type":           []string{"offline"},
								"client_id":             []string{"test-client-id"},
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"upstream-idp-name-with-cli-password-flow-first"},
								"pinniped_idp_type":     []string{"upstream-idp-type-with-cli-password-flow-first"},
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantToken:  &testToken,
		},
		{
			name:     "unable to login with unknown IDP, when Supervisor provides its supported IDP types",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.generateState = func() (state.State, error) { return "test-state", nil }
					h.generatePKCE = func() (pkce.Code, error) { return "test-pkce", nil }
					h.generateNonce = func() (nonce.Nonce, error) { return "test-nonce", nil }
					h.getEnv = func(_ string) string {
						return "" // asking for any env var returns empty as if it were unset
					}
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "some-upstream-username", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Password: ", promptLabel)
						return "some-upstream-password", nil
					}

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey(nil), cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token(nil), cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "INVALID UPSTREAM TYPE")(h))

					discoveryRequestWasMade := false
					idpDiscoveryRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, idpDiscoveryRequestWasMade, "should have made an discovery request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							idpDiscoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
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
			issuer:   successServer.URL,
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantErr:  `unable to find upstream identity provider with type "INVALID UPSTREAM TYPE", this Pinniped Supervisor supports IDP types ["upstream-idp-type-with-browser-authcode-flow-first", "upstream-idp-type-with-cli-password-flow-first"]`,
		},
		{
			name:     "successful ldap login with prompts for username and password, using deprecated WithCLISendingCredentials option",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "some-upstream-username", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Password: ", promptLabel)
						return "some-upstream-password", nil
					}

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithCLISendingCredentials()(h)) // This is meant to call a deprecated function
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "upstream-idp-type-with-cli-password-flow-first")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
							require.Equal(t, url.Values{
								"code_challenge":        []string{testCodeChallenge},
								"code_challenge_method": []string{"S256"},
								"response_type":         []string{"code"},
								"scope":                 []string{"test-scope"},
								"nonce":                 []string{"test-nonce"},
								"state":                 []string{"test-state"},
								"access_type":           []string{"offline"},
								"client_id":             []string{"test-client-id"},
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"upstream-idp-name-with-cli-password-flow-first"},
								"pinniped_idp_type":     []string{"upstream-idp-type-with-cli-password-flow-first"},
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantToken:  &testToken,
		},
		{
			name:     "successful ldap login with prompts for username and password, infers flow when not specified",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Username: ", promptLabel)
						return "some-upstream-username", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
						require.Equal(t, "Password: ", promptLabel)
						return "some-upstream-password", nil
					}

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "upstream-idp-type-with-cli-password-flow-first")(h))

					discoveryRequestWasMade := false
					idpDiscoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, idpDiscoveryRequestWasMade, "should have made an IDP discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							idpDiscoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
							require.Equal(t, url.Values{
								"code_challenge":        []string{testCodeChallenge},
								"code_challenge_method": []string{"S256"},
								"response_type":         []string{"code"},
								"scope":                 []string{"test-scope"},
								"nonce":                 []string{"test-nonce"},
								"state":                 []string{"test-state"},
								"access_type":           []string{"offline"},
								"client_id":             []string{"test-client-id"},
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"upstream-idp-name-with-cli-password-flow-first"},
								"pinniped_idp_type":     []string{"upstream-idp-type-with-cli-password-flow-first"},
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
			issuer:     successServer.URL,
			wantLogs:   []string{`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantToken:  &testToken,
		},
		{
			name:     "successful ldap login with env vars for username and password",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
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
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
							require.Equal(t, url.Values{
								"code_challenge":        []string{testCodeChallenge},
								"code_challenge_method": []string{"S256"},
								"response_type":         []string{"code"},
								"scope":                 []string{"test-scope"},
								"nonce":                 []string{"test-nonce"},
								"state":                 []string{"test-state"},
								"access_type":           []string{"offline"},
								"client_id":             []string{"test-client-id"},
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
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
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Read username from environment variable"  "name"="PINNIPED_USERNAME"`,
				`"level"=4 "msg"="Pinniped: Read password from environment variable"  "name"="PINNIPED_PASSWORD"`,
			},
			wantToken: &testToken,
		},
		{
			name:     "successful ldap login with env vars for username and password, http.StatusSeeOther redirect",
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					fakeAuthCode := "test-authcode-value"

					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}
					h.promptForSecret = func(promptLabel string, _ io.Writer) (string, error) {
						require.FailNow(t, fmt.Sprintf("saw unexpected prompt from the CLI: %q", promptLabel))
						return "", nil
					}

					cache := &mockSessionCache{t: t, getReturnsToken: nil}
					cacheKey := SessionCacheKey{
						Issuer:               successServer.URL,
						ClientID:             "test-client-id",
						Scopes:               []string{"test-scope"},
						RedirectURI:          "http://localhost:0/callback",
						UpstreamProviderName: "upstream-idp-name-with-cli-password-flow-first",
					}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawGetKeys)
						require.Equal(t, []SessionCacheKey{cacheKey}, cache.sawPutKeys)
						require.Equal(t, []*oidctypes.Token{&testToken}, cache.sawPutTokens)
					})
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "flowSource")(h))
					require.NoError(t, WithUpstreamIdentityProvider("upstream-idp-name-with-cli-password-flow-first", "upstream-idp-type-with-cli-password-flow-first")(h))

					discoveryRequestWasMade := false
					authorizeRequestWasMade := false
					t.Cleanup(func() {
						require.True(t, discoveryRequestWasMade, "should have made an discovery request")
						require.True(t, authorizeRequestWasMade, "should have made an authorize request")
					})

					client := buildHTTPClientForPEM(successServerCA)
					client.Transport = roundtripper.Func(func(req *http.Request) (*http.Response, error) {
						switch req.URL.Scheme + "://" + req.URL.Host + req.URL.Path {
						case "https://" + successServer.Listener.Addr().String() + "/.well-known/openid-configuration":
							discoveryRequestWasMade = true
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + federationdomainoidc.PinnipedIDPsPathV1Alpha1:
							return defaultDiscoveryResponse(req)
						case "https://" + successServer.Listener.Addr().String() + "/authorize":
							authorizeRequestWasMade = true
							require.Equal(t, "some-upstream-username", req.Header.Get("Pinniped-Username"))
							require.Equal(t, "some-upstream-password", req.Header.Get("Pinniped-Password"))
							require.Equal(t, url.Values{
								"code_challenge":        []string{testCodeChallenge},
								"code_challenge_method": []string{"S256"},
								"response_type":         []string{"code"},
								"scope":                 []string{"test-scope"},
								"nonce":                 []string{"test-nonce"},
								"state":                 []string{"test-state"},
								"access_type":           []string{"offline"},
								"client_id":             []string{"test-client-id"},
								"redirect_uri":          []string{"http://127.0.0.1:0/callback"},
								"pinniped_idp_name":     []string{"upstream-idp-name-with-cli-password-flow-first"},
								"pinniped_idp_type":     []string{"upstream-idp-type-with-cli-password-flow-first"},
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
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Read username from environment variable"  "name"="PINNIPED_USERNAME"`,
				`"level"=4 "msg"="Pinniped: Read password from environment variable"  "name"="PINNIPED_PASSWORD"`,
			},
			wantStdErr: "^\nLog in to upstream-idp-name-with-cli-password-flow-first\n\n$",
			wantToken:  &testToken,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but discovery fails",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(errorServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="cluster-1234"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + errorServer.URL + `"`,
			},
			wantErr: fmt.Sprintf("failed to exchange token: could not perform OIDC discovery for %q: 500 Internal Server Error: some discovery error\n", errorServer.URL),
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token URL is insecure",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(insecureTokenURLServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="cluster-1234"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + insecureTokenURLServer.URL + `"`,
			},
			wantErr: `failed to exchange token: discovered token URL from issuer must be an https URL, but had scheme "http" instead`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token URL is invalid",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(brokenTokenURLServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("cluster-1234")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="cluster-1234"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + brokenTokenURLServer.URL + `"`,
			},
			wantErr: `failed to exchange token: discovered token URL from issuer is not a valid URL: parse "%": invalid URL escape "%"`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request fails",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-http-response")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-http-response"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: fmt.Sprintf(`failed to exchange token: Post "%s/token": failed to parse Location header "%%": parse "%%": invalid URL escape "%%"`, successServer.URL),
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns non-200",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-http-400")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-http-400"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: unexpected HTTP response status 400`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns invalid content-type header",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-content-type")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-content-type"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: failed to decode content-type header: mime: invalid media parameter`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns wrong content-type",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-wrong-content-type")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-wrong-content-type"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: unexpected HTTP response content type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns invalid JSON",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-json")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-json"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: failed to decode response: unexpected EOF`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns invalid token_type",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-tokentype")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-tokentype"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: got unexpected token_type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns invalid issued_token_type",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-issuedtokentype")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-issuedtokentype"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: got unexpected issued_token_type "invalid"`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but token exchange request returns invalid JWT",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience-produce-invalid-jwt")(h))
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience-produce-invalid-jwt"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantErr: `failed to exchange token: received invalid JWT: oidc: malformed jwt: oidc: malformed jwt, expected 3 parts got 1`,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, ID token has wrong audience, and token exchange request succeeds",
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
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-audience")(h))

					h.validateIDToken = func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
						require.Equal(t, "test-audience", audience)
						require.Equal(t, "test-id-token-with-requested-audience", token)
						return &coreosoidc.IDToken{Expiry: testExchangedToken.IDToken.Expiry.Time}, nil
					}
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantToken: &testExchangedToken,
		},
		{
			name:     "with requested audience, session cache hit with valid access token, and valid ID token already has the requested audience, returns cached tokens without any exchange or refresh",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						AccessToken: testToken.AccessToken,
						IDToken: &oidctypes.IDToken{
							Token:  testToken.IDToken.Token,
							Expiry: testToken.IDToken.Expiry,
							Claims: map[string]any{"aud": "request-this-test-audience"},
						},
						RefreshToken: testToken.RefreshToken,
					}}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("request-this-test-audience")(h))

					h.validateIDToken = func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
						require.FailNow(t, "should not have performed a token exchange because the cached ID token already had the requested audience")
						return nil, nil
					}
					return nil
				}
			},
			wantLogs: []string{`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="id_token"`},
			wantToken: &oidctypes.Token{ // the same tokens that were pulled from the cache
				AccessToken: testToken.AccessToken,
				IDToken: &oidctypes.IDToken{
					Token:  testToken.IDToken.Token,
					Expiry: testToken.IDToken.Expiry,
					Claims: map[string]any{"aud": "request-this-test-audience"},
				},
				RefreshToken: testToken.RefreshToken,
			},
		},
		{
			name:     "with requested audience, session cache hit with valid access token, ID token already has the requested audience, but ID token is expired, causes a refresh and uses refreshed ID token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						AccessToken: testToken.AccessToken,
						IDToken: &oidctypes.IDToken{
							Token:  testToken.IDToken.Token,
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Minute)), // less than Now() + minIDTokenValidity
							Claims: map[string]any{"aud": "test-custom-request-audience"},
						},
						RefreshToken: testToken.RefreshToken,
					}}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Len(t, cache.sawPutTokens, 1)
						// want to have cached the refreshed ID token
						require.Equal(t, &oidctypes.IDToken{
							Token:  testToken.IDToken.Token,
							Expiry: metav1.NewTime(fakeUniqueTime),
							Claims: map[string]any{"aud": "test-custom-request-audience"},
						}, cache.sawPutTokens[0].IDToken)
					})
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("test-custom-request-audience")(h))

					h.getProvider = func(config *oauth2.Config, provider *coreosoidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ValidateTokenAndMergeWithUserInfo(gomock.Any(), HasAccessToken(testToken.AccessToken.Token), nonce.Nonce(""), true, false).
							Return(&oidctypes.Token{
								AccessToken: testToken.AccessToken,
								IDToken: &oidctypes.IDToken{
									Token:  testToken.IDToken.Token,
									Expiry: metav1.NewTime(fakeUniqueTime), // less than Now() + minIDTokenValidity but does not matter because this is a freshly refreshed ID token
									Claims: map[string]any{"aud": "test-custom-request-audience"},
								},
								RefreshToken: testToken.RefreshToken,
							}, nil)
						mock.EXPECT().
							PerformRefresh(gomock.Any(), testToken.RefreshToken.Token).
							DoAndReturn(func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
								// Call the real production code to perform a refresh.
								return upstreamoidc.New(config, provider, client).PerformRefresh(ctx, refreshToken)
							})
						return mock
					}
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached tokens."`,
			},
			// want to have returned the refreshed tokens
			wantToken: &oidctypes.Token{
				AccessToken: testToken.AccessToken,
				IDToken: &oidctypes.IDToken{
					Token:  testToken.IDToken.Token,
					Expiry: metav1.NewTime(fakeUniqueTime),
					Claims: map[string]any{"aud": "test-custom-request-audience"},
				},
				RefreshToken: testToken.RefreshToken,
			},
		},
		{
			name:     "with requested audience, session cache hit with valid access token, but no ID token",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						AccessToken:  testToken.AccessToken,
						RefreshToken: testToken.RefreshToken,
					}}
					t.Cleanup(func() {
						require.Equal(t, []SessionCacheKey{{
							Issuer:      successServer.URL,
							ClientID:    "test-client-id",
							Scopes:      []string{"test-scope"},
							RedirectURI: "http://localhost:0/callback",
						}}, cache.sawGetKeys)
						require.Empty(t, cache.sawPutTokens)
					})
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))
					require.NoError(t, WithSessionCache(cache)(h))
					require.NoError(t, WithRequestAudience("request-this-test-audience")(h))

					h.validateIDToken = func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
						require.Equal(t, "request-this-test-audience", audience)
						require.Equal(t, "test-id-token-with-requested-audience", token)
						return &coreosoidc.IDToken{Expiry: testExchangedToken.IDToken.Expiry.Time}, nil
					}
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Found unexpired cached token."  "type"="access_token"`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="request-this-test-audience"`,
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
			},
			wantToken: &testExchangedToken,
		},
		{
			name:     "with requested audience, session cache hit with expired access token and valid refresh token, and token exchange request succeeds",
			issuer:   successServer.URL,
			clientID: "test-client-id",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					require.NoError(t, WithClient(buildHTTPClientForPEM(successServerCA))(h))

					cache := &mockSessionCache{t: t, getReturnsToken: &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "not-yet-expired-test-id-token",
							Expiry: metav1.NewTime(distantFutureTime),
						},
						AccessToken: &oidctypes.AccessToken{
							Token:  "expired-test-access-token",
							Expiry: metav1.NewTime(time.Now().Add(9 * time.Second)), // less than Now() + minAccessTokenValidity
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

					h.getProvider = func(config *oauth2.Config, provider *coreosoidc.Provider, client *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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

					h.validateIDToken = func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
						require.Equal(t, "test-audience", audience)
						require.Equal(t, "test-id-token-with-requested-audience", token)
						return &coreosoidc.IDToken{Expiry: testExchangedToken.IDToken.Expiry.Time}, nil
					}
					return nil
				}
			},
			wantLogs: []string{
				`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + successServer.URL + `"`,
				`"level"=4 "msg"="Pinniped: Refreshing cached tokens."`,
				`"level"=4 "msg"="Pinniped: Performing RFC8693 token exchange"  "requestedAudience"="test-audience"`,
			},
			wantToken: &testExchangedToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger := testlogger.NewLegacy(t) //nolint:staticcheck  // old test with lots of log statements
			klog.SetLogger(testLogger.Logger)     // this is unfortunately a global logger, so can't run these tests in parallel :(
			t.Cleanup(func() {
				klog.ClearLogger()
			})

			buffer := bytes.Buffer{}
			tok, err := Login(tt.issuer, tt.clientID,
				WithContext(context.Background()),
				WithListenPort(0),
				WithScopes([]string{"test-scope"}),
				WithSkipBrowserOpen(), // Skip by default so we don't really open a browser. Each test can override this.
				tt.opt(t),
				WithLogger(testLogger.Logger),
				withOutWriter(t, &buffer),
			)

			testLogger.Expect(tt.wantLogs)

			if tt.wantStdErr == "" {
				require.Empty(t, buffer.String())
			} else {
				require.Regexp(t, tt.wantStdErr, buffer.String())
			}

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

func withOutWriter(t *testing.T, out io.Writer) Option {
	return func(h *handlerState) error {
		// Ensure that the proper default value has been set in the handlerState prior to overriding it for tests.
		require.Equal(t, os.Stderr, h.out)
		h.out = out
		return nil
	}
}

func TestHandlePasteCallback(t *testing.T) {
	const testRedirectURI = "http://127.0.0.1:12324/callback"
	const testAuthURL = "https://test-authorize-url/"
	const cancelledAuthcodePromptOutput = "[...]\n"
	const newlineAfterEveryAuthcodePromptOutput = "\n"

	expectedAuthURLOutput := func(expectedAuthURL string) string {
		return fmt.Sprintf("Log in by visiting this link:\n\n    %s\n\n", expectedAuthURL)
	}

	tests := []struct {
		name              string
		opt               func(t *testing.T) Option
		authorizeURL      string
		printAuthorizeURL bool

		wantStderr   string
		wantCallback *callbackResult
	}{
		{
			name: "no stdin available",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return false }
					h.useFormPost = true
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: true,
			wantStderr:        expectedAuthURLOutput(testAuthURL),
		},
		{
			name: "no form_post mode available",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return true }
					h.useFormPost = false
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: true,
			wantStderr:        expectedAuthURLOutput(testAuthURL),
		},
		{
			name: "prompt fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						assert.Equal(t, "    Optionally, paste your authorization code: ", promptLabel)
						return "", fmt.Errorf("some prompt error")
					}
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: true,
			wantStderr:        expectedAuthURLOutput(testAuthURL) + cancelledAuthcodePromptOutput + newlineAfterEveryAuthcodePromptOutput,
			wantCallback: &callbackResult{
				err: fmt.Errorf("failed to prompt for manual authorization code: some prompt error"),
			},
		},
		{
			name: "redeeming code fails",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						return "invalid", nil
					}
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "invalid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(nil, fmt.Errorf("some exchange error"))
						return mock
					}
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: true,
			wantStderr:        expectedAuthURLOutput(testAuthURL) + newlineAfterEveryAuthcodePromptOutput,
			wantCallback: &callbackResult{
				err: fmt.Errorf("some exchange error"),
			},
		},
		{
			name: "success, with printing auth url",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return true }
					h.useFormPost = true
					h.promptForValue = func(_ context.Context, promptLabel string, _ io.Writer) (string, error) {
						return "valid", nil
					}
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
						return mock
					}
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: true,
			wantStderr:        expectedAuthURLOutput(testAuthURL) + newlineAfterEveryAuthcodePromptOutput,
			wantCallback: &callbackResult{
				token: &oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}},
			},
		},
		{
			name: "skipping printing auth url (also skips prompting for authcode)",
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.stdinIsTTY = func() bool { return true }
					h.useFormPost = true
					h.promptForValue = nil // shouldn't get called, so can be nil
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
						mock := mockUpstream(t)
						mock.EXPECT().
							ExchangeAuthcodeAndValidateTokens(gomock.Any(), "valid", pkce.Code("test-pkce"), nonce.Nonce("test-nonce"), testRedirectURI).
							Return(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: "test-id-token"}}, nil)
						return mock
					}
					return nil
				}
			},
			authorizeURL:      testAuthURL,
			printAuthorizeURL: false, // do not want to print auth URL
			wantStderr:        "",    // auth URL was not printed, and prompt for pasting authcode was also not printed
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := &bytes.Buffer{}
			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
				out:       buf,
			}
			if tt.opt != nil {
				require.NoError(t, tt.opt(t)(h))
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			cleanupPrompt := h.promptForWebLogin(ctx, tt.authorizeURL, tt.printAuthorizeURL)

			if tt.wantCallback != nil {
				select {
				case <-time.After(1 * time.Second):
					require.Fail(t, "timed out waiting to receive from callbacks channel")
				case result := <-h.callbacks:
					require.Equal(t, *tt.wantCallback, result)
				}
			}

			// Reading buf before the goroutine inside of promptForWebLogin finishes is a data race,
			// because that goroutine will also try to write to buf.
			// Avoid this by shutting down its goroutine by cancelling its context,
			// and clean it up with its cleanup function (which waits for it to be done).
			// Then it should always be safe to read buf.
			cancel()
			cleanupPrompt()
			require.Equal(t, tt.wantStderr, buf.String())
		})
	}
}

func TestHandleAuthCodeCallback(t *testing.T) {
	const testRedirectURI = "http://127.0.0.1:12324/callback"

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
			method:          http.MethodHead,
			query:           "",
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
			wantErr:        `invalid form: invalid URL escape "%"`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:    "invalid state",
			method:  http.MethodGet,
			query:   "state=invalid",
			wantErr: "missing or invalid state parameter",
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
			},
			wantHTTPStatus: http.StatusForbidden,
		},
		{
			name:    "error code from provider",
			method:  http.MethodGet,
			query:   "state=test-state&error=some_error",
			wantErr: `login failed with code "some_error"`,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
			},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:    "error code with a description from provider",
			method:  http.MethodGet,
			query:   "state=test-state&error=some_error&error_description=optional%20error%20description",
			wantErr: `login failed with code "some_error": optional error description`,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
			},
			wantHTTPStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid issuer url config during CORS preflight request returns an error",
			method:         http.MethodOptions,
			query:          "",
			headers:        map[string][]string{"Origin": {"https://some-origin.com"}},
			wantErr:        `invalid issuer url: parse "://bad-url": missing protocol scheme`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusInternalServerError,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.issuer = "://bad-url"
					return nil
				}
			},
		},
		{
			name:           "invalid issuer url config during POST request returns an error",
			method:         http.MethodPost,
			query:          "",
			headers:        map[string][]string{"Origin": {"https://some-origin.com"}},
			wantErr:        `invalid issuer url: parse "://bad-url": missing protocol scheme`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusInternalServerError,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.issuer = "://bad-url"
					return nil
				}
			},
		},
		{
			name:           "invalid issuer url config during GET request returns an error",
			method:         http.MethodGet,
			query:          "code=foo",
			headers:        map[string][]string{},
			wantErr:        `invalid issuer url: parse "://bad-url": missing protocol scheme`,
			wantHeaders:    map[string][]string{},
			wantHTTPStatus: http.StatusInternalServerError,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.issuer = "://bad-url"
					return nil
				}
			},
		},
		{
			name:            "options request is missing origin header results in 400 and keeps listener running",
			method:          http.MethodOptions,
			query:           "",
			wantNoCallbacks: true,
			wantHeaders:     map[string][]string{},
			wantHTTPStatus:  http.StatusBadRequest,
		},
		{
			name:            "valid CORS request responds with 402 and CORS headers and keeps listener running",
			method:          http.MethodOptions,
			query:           "",
			headers:         map[string][]string{"Origin": {"https://some-origin.com"}},
			wantNoCallbacks: true,
			wantHTTPStatus:  http.StatusNoContent,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Credentials":     {"false"},
				"Access-Control-Allow-Methods":         {"GET, POST, OPTIONS"},
				"Access-Control-Allow-Origin":          {"https://valid-issuer.com"},
				"Vary":                                 {"*"},
				"Access-Control-Allow-Private-Network": {"true"},
			},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.issuer = "https://valid-issuer.com/with/some/path"
					return nil
				}
			},
		},
		{
			name:   "valid CORS request with Access-Control-Request-Headers responds with 402 and CORS headers including Access-Control-Allow-Headers and keeps listener running",
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
				"Access-Control-Allow-Methods":         {"GET, POST, OPTIONS"},
				"Access-Control-Allow-Origin":          {"https://valid-issuer.com"},
				"Vary":                                 {"*"},
				"Access-Control-Allow-Private-Network": {"true"},
				"Access-Control-Allow-Headers":         {"header1, header2, header3"},
			},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.issuer = "https://valid-issuer.com/with/some/path"
					return nil
				}
			},
		},
		{
			name:    "invalid code",
			method:  http.MethodGet,
			query:   "state=test-state&code=invalid",
			wantErr: "could not complete authorization code exchange: some exchange error",
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
			},
			wantHTTPStatus: http.StatusBadRequest,
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
			method:         http.MethodGet,
			query:          "state=test-state&code=valid",
			wantHTTPStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Access-Control-Allow-Origin": {"https://valid-issuer.com"},
				"Vary":                        {"*"},
				"Content-Type":                {"text/plain; charset=utf-8"},
			},
			opt: func(t *testing.T) Option {
				return func(h *handlerState) error {
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
					h.oauth2Config = &oauth2.Config{RedirectURL: testRedirectURI}
					h.getProvider = func(_ *oauth2.Config, _ *coreosoidc.Provider, _ *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI {
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &handlerState{
				callbacks: make(chan callbackResult, 1),
				state:     state.State("test-state"),
				pkce:      pkce.Code("test-pkce"),
				nonce:     nonce.Nonce("test-nonce"),
				logger:    plog.New(),
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

			require.NotEmptyf(t, tt.method, "test author mistake: method is required on the test table entry")
			req.Method = tt.method

			req.URL.RawQuery = tt.query
			if tt.headers != nil {
				req.Header = tt.headers
			}

			err = h.handleAuthCodeCallback(resp, req)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				rec := httptest.NewRecorder()
				err.(httperr.Responder).Respond(rec)
				require.Equal(t, tt.wantHTTPStatus, rec.Code)
				// The error message returned (to be shown by the CLI) and the error message shown in the resulting
				// web page should always be the same.
				require.Equal(t, http.StatusText(tt.wantHTTPStatus)+": "+tt.wantErr+"\n", rec.Body.String())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantHTTPStatus, resp.Code)
				switch {
				case tt.wantNoCallbacks:
					// When we return an error but keep listening, then we don't need a response body.
					require.Empty(t, resp.Body)
				case tt.wantHTTPStatus == http.StatusOK:
					// When the login succeeds, the response body should show the success message.
					require.Equal(t, "you have been logged in and may now close this tab", resp.Body.String())
				default:
					t.Fatal("test author made a mistake by expecting a non-200 response code without a wantErr")
				}
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
					require.Nil(t, result.token)
				} else {
					require.NoError(t, result.err)
					require.NotNil(t, result.token)
					require.Equal(t, result.token.IDToken.Token, "test-id-token")
				}
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

func (m hasAccessTokenMatcher) Matches(arg any) bool {
	return arg.(*oauth2.Token).AccessToken == m.expected
}

func (m hasAccessTokenMatcher) Got(got any) string {
	return got.(*oauth2.Token).AccessToken
}

func (m hasAccessTokenMatcher) String() string {
	return m.expected
}

func HasAccessToken(expected string) gomock.Matcher {
	return hasAccessTokenMatcher{expected: expected}
}

func TestMaybePerformPinnipedSupervisorIDPDiscovery(t *testing.T) {
	withContextAndProvider := func(t *testing.T, issuerURL string) Option {
		return func(h *handlerState) error {
			t.Helper()

			cancelCtx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			h.ctx = cancelCtx

			cancelCtx = coreosoidc.ClientContext(cancelCtx, h.httpClient)
			provider, err := coreosoidc.NewProvider(cancelCtx, issuerURL)
			require.NoError(t, err)
			h.provider = provider
			return nil
		}
	}

	t.Run("with valid IDP discovery information, returns the information", func(t *testing.T) {
		issuerMux := http.NewServeMux()
		issuerServer, issuerServerCA := tlsserver.TestServerIPv4(t, issuerMux, nil)

		oidcDiscoveryMetadata := discovery.Metadata{
			Issuer: issuerServer.URL,
			OIDCDiscoveryResponse: idpdiscoveryv1alpha1.OIDCDiscoveryResponse{
				SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
					PinnipedIDPsEndpoint: issuerServer.URL + "/some-path-for-pinnipeds-idp-discovery",
				},
			},
		}

		idpDiscoveryMetadata := &idpdiscoveryv1alpha1.IDPDiscoveryResponse{
			PinnipedIDPs: []idpdiscoveryv1alpha1.PinnipedIDP{
				{
					Name:  "some-idp-name",
					Type:  "some-idp-type",
					Flows: []idpdiscoveryv1alpha1.IDPFlow{"some-flow", "some-other-flow"},
				},
			},
			PinnipedSupportedIDPTypes: []idpdiscoveryv1alpha1.PinnipedSupportedIDPType{
				{Type: "type-alpha"},
				{Type: "type-beta"},
				{Type: "type-gamma"},
			},
		}

		issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			jsonBytes, err := json.Marshal(&oidcDiscoveryMetadata)
			require.NoError(t, err)
			_, err = w.Write(jsonBytes)
			require.NoError(t, err)
		})

		issuerMux.HandleFunc("/some-path-for-pinnipeds-idp-discovery", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			jsonBytes, err := json.Marshal(idpDiscoveryMetadata)
			require.NoError(t, err)
			_, err = w.Write(jsonBytes)
			require.NoError(t, err)
		})

		var h handlerState
		require.NoError(t, WithClient(buildHTTPClientForPEM(issuerServerCA))(&h))
		require.NoError(t, withContextAndProvider(t, issuerServer.URL)(&h))

		actualError := h.maybePerformPinnipedSupervisorIDPDiscovery()
		require.NoError(t, actualError)
		require.Equal(t, idpDiscoveryMetadata, h.idpDiscovery)
	})

	t.Run("when IDP discovery returns 500, return an error", func(t *testing.T) {
		issuerMux := http.NewServeMux()
		issuerServer, issuerServerCA := tlsserver.TestServerIPv4(t, issuerMux, nil)

		oidcDiscoveryMetadata := discovery.Metadata{
			Issuer: issuerServer.URL,
			OIDCDiscoveryResponse: idpdiscoveryv1alpha1.OIDCDiscoveryResponse{
				SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
					PinnipedIDPsEndpoint: issuerServer.URL + "/some-path-for-pinnipeds-idp-discovery",
				},
			},
		}

		issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			jsonBytes, err := json.Marshal(&oidcDiscoveryMetadata)
			require.NoError(t, err)
			_, err = w.Write(jsonBytes)
			require.NoError(t, err)
		})

		issuerMux.HandleFunc("/some-path-for-pinnipeds-idp-discovery", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		var h handlerState
		require.NoError(t, WithClient(buildHTTPClientForPEM(issuerServerCA))(&h))
		require.NoError(t, withContextAndProvider(t, issuerServer.URL)(&h))

		actualError := h.maybePerformPinnipedSupervisorIDPDiscovery()
		require.EqualError(t, actualError, "unable to fetch IDP discovery data from issuer: unexpected http response status: 500 Internal Server Error")
		require.Empty(t, h.idpDiscovery)
	})

	t.Run("when IDP discovery returns garbled data, return an error", func(t *testing.T) {
		issuerMux := http.NewServeMux()
		issuerServer, issuerServerCA := tlsserver.TestServerIPv4(t, issuerMux, nil)

		oidcDiscoveryMetadata := discovery.Metadata{
			Issuer: issuerServer.URL,
			OIDCDiscoveryResponse: idpdiscoveryv1alpha1.OIDCDiscoveryResponse{
				SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
					PinnipedIDPsEndpoint: issuerServer.URL + "/some-path-for-pinnipeds-idp-discovery",
				},
			},
		}

		issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			jsonBytes, err := json.Marshal(&oidcDiscoveryMetadata)
			require.NoError(t, err)
			_, err = w.Write(jsonBytes)
			require.NoError(t, err)
		})

		issuerMux.HandleFunc("/some-path-for-pinnipeds-idp-discovery", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			_, err := w.Write([]byte("foo"))
			require.NoError(t, err)
		})

		var h handlerState
		require.NoError(t, WithClient(buildHTTPClientForPEM(issuerServerCA))(&h))
		require.NoError(t, withContextAndProvider(t, issuerServer.URL)(&h))

		actualError := h.maybePerformPinnipedSupervisorIDPDiscovery()
		require.EqualError(t, actualError, "unable to fetch the Pinniped IDP discovery document: could not parse response JSON: invalid character 'o' in literal false (expecting 'a')")
		require.Empty(t, h.idpDiscovery)
	})

	t.Run("when http client cannot perform request, return an error", func(t *testing.T) {
		issuerMux := http.NewServeMux()
		issuerServer, issuerServerCA := tlsserver.TestServerIPv4(t, issuerMux, nil)

		oidcDiscoveryMetadata := discovery.Metadata{
			Issuer: issuerServer.URL,
			OIDCDiscoveryResponse: idpdiscoveryv1alpha1.OIDCDiscoveryResponse{
				SupervisorDiscovery: idpdiscoveryv1alpha1.OIDCDiscoveryResponseIDPEndpoint{
					PinnipedIDPsEndpoint: issuerServer.URL + "/some-path-for-pinnipeds-idp-discovery",
				},
			},
		}

		issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			jsonBytes, err := json.Marshal(&oidcDiscoveryMetadata)
			require.NoError(t, err)
			_, err = w.Write(jsonBytes)
			require.NoError(t, err)
		})

		issuerMux.HandleFunc("/some-path-for-pinnipeds-idp-discovery", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "foo")
			w.WriteHeader(http.StatusSeeOther)
		})

		var h handlerState
		require.NoError(t, WithClient(buildHTTPClientForPEM(issuerServerCA))(&h))
		require.NoError(t, withContextAndProvider(t, issuerServer.URL)(&h))
		h.httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirect error")
		}

		actualError := h.maybePerformPinnipedSupervisorIDPDiscovery()
		require.EqualError(t, actualError, `IDP Discovery response error: Get "foo": redirect error`)
		require.Empty(t, h.idpDiscovery)
	})

	tests := []struct {
		name              string
		pinnipedDiscovery string
		wantErr           string
	}{
		{
			name: "when not a Supervisor, returns nothing",
		},
		{
			name:              "when the Supervisor returns empty discovery information, returns nothing",
			pinnipedDiscovery: `{"pinniped_identity_providers_endpoint":""}`,
		},
		{
			name:              "when the Supervisor returns invalid discovery information, returns an error",
			pinnipedDiscovery: `"not-valid-discovery-claim"`,
			wantErr:           `could not decode the Pinniped IDP discovery document URL in OIDC discovery from "FAKE-ISSUER": json: cannot unmarshal string into Go struct field OIDCDiscoveryResponse.discovery.supervisor.pinniped.dev/v1alpha1 of type v1alpha1.OIDCDiscoveryResponseIDPEndpoint`,
		},
		{
			name:              "when the Supervisor has invalid pinniped_identity_providers_endpoint, returns an error",
			pinnipedDiscovery: `{"pinniped_identity_providers_endpoint":"asdf"}`,
			wantErr:           `the Pinniped IDP discovery document must always be hosted by the issuer: "FAKE-ISSUER"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			issuerMux := http.NewServeMux()
			issuerServer, issuerServerCA := tlsserver.TestServerIPv4(t, issuerMux, nil)

			issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				_, _ = fmt.Fprintf(w, `{"issuer": %q`, issuerServer.URL)
				if len(test.pinnipedDiscovery) > 0 {
					_, _ = fmt.Fprintf(w, `, "discovery.supervisor.pinniped.dev/v1alpha1": %s`, test.pinnipedDiscovery)
				}
				_, _ = fmt.Fprint(w, `}`)
			})

			var h handlerState
			h.issuer = "FAKE-ISSUER"
			require.NoError(t, WithClient(buildHTTPClientForPEM(issuerServerCA))(&h))
			require.NoError(t, withContextAndProvider(t, issuerServer.URL)(&h))

			actualError := h.maybePerformPinnipedSupervisorIDPDiscovery()

			if test.wantErr != "" {
				require.EqualError(t, actualError, test.wantErr)
				return
			}

			require.NoError(t, actualError)
		})
	}
}

func TestMaybePerformPinnipedSupervisorValidations(t *testing.T) {
	withIDPDiscovery := func(idpDiscovery idpdiscoveryv1alpha1.IDPDiscoveryResponse) Option {
		return func(h *handlerState) error {
			h.idpDiscovery = &idpDiscovery
			return nil
		}
	}

	withIssuer := func(issuer string) Option {
		return func(h *handlerState) error {
			h.issuer = issuer
			return nil
		}
	}

	someIDPDiscoveryResponse := idpdiscoveryv1alpha1.IDPDiscoveryResponse{
		PinnipedIDPs: []idpdiscoveryv1alpha1.PinnipedIDP{
			{
				Name: "some-upstream-name",
				Type: "some-upstream-type",
				Flows: []idpdiscoveryv1alpha1.IDPFlow{
					idpdiscoveryv1alpha1.IDPFlowCLIPassword,
					idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode,
				},
			},
			{
				Name: "idp-name-with-cli-password-only-flow",
				Type: "idp-type-with-cli-password-only-flow",
				Flows: []idpdiscoveryv1alpha1.IDPFlow{
					idpdiscoveryv1alpha1.IDPFlowCLIPassword,
				},
			},
			{
				Name: "idp-name-with-no-flows",
				Type: "idp-type-with-no-flows",
			},
		},
		PinnipedSupportedIDPTypes: []idpdiscoveryv1alpha1.PinnipedSupportedIDPType{
			{Type: "some-upstream-type"},
			{Type: "idp-type-with-cli-password-only-flow"},
			{Type: "idp-type-with-no-flows"},
			{Type: "other-supported-type-with-no-idp"},
		},
	}
	stringVersionOfSomeIDPDiscoveryResponseIDPs := `[{"name":"some-upstream-name","type":"some-upstream-type","flows":["cli_password","browser_authcode"]},{"name":"idp-name-with-cli-password-only-flow","type":"idp-type-with-cli-password-only-flow","flows":["cli_password"]},{"name":"idp-name-with-no-flows","type":"idp-type-with-no-flows"}]`

	tests := []struct {
		name                string
		options             []Option
		wantAuthCodeOptions []oauth2.AuthCodeOption
		wantLoginFlow       idpdiscoveryv1alpha1.IDPFlow
		wantErr             string
	}{
		{
			name: "without IDP name, return the specified login flow, nil options, and no error",
			options: []Option{
				WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "someSource"),
			},
			wantLoginFlow:       idpdiscoveryv1alpha1.IDPFlowCLIPassword,
			wantAuthCodeOptions: nil,
		},
		{
			name: "with IDP name and IDP type, returns the right AuthCodeOptions and infers the loginFlow",
			options: []Option{
				WithUpstreamIdentityProvider("some-upstream-name", "some-upstream-type"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantAuthCodeOptions: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPNameParamName, "some-upstream-name"),
				oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPTypeParamName, "some-upstream-type"),
			},
			wantLoginFlow: idpdiscoveryv1alpha1.IDPFlowCLIPassword,
		},
		{
			name: "when the Supervisor lists pinniped_supported_identity_provider_types and the given upstreamType is not found, return a specific error",
			options: []Option{
				WithUpstreamIdentityProvider("some-upstream-name", "NOT_A_DISCOVERED_TYPE"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantErr: `unable to find upstream identity provider with type "NOT_A_DISCOVERED_TYPE", this Pinniped Supervisor supports IDP types ["idp-type-with-cli-password-only-flow", "idp-type-with-no-flows", "other-supported-type-with-no-idp", "some-upstream-type"]`,
		},
		{
			name: "when the Supervisor does not list pinniped_supported_identity_provider_types (legacy behavior) and the given upstreamType is not found, return a generic error",
			options: []Option{
				WithUpstreamIdentityProvider("some-upstream-name", "NOT_A_DISCOVERED_TYPE"),
				withIDPDiscovery(func() idpdiscoveryv1alpha1.IDPDiscoveryResponse {
					temp := someIDPDiscoveryResponse
					temp.PinnipedSupportedIDPTypes = nil
					return temp
				}()),
			},
			wantErr: `unable to find upstream identity provider with name "some-upstream-name" and type "NOT_A_DISCOVERED_TYPE". Found these providers: ` +
				stringVersionOfSomeIDPDiscoveryResponseIDPs,
		},
		{
			name: "when the Supervisor does not have an IDP that matches by name, return an error",
			options: []Option{
				WithUpstreamIdentityProvider("INVALID-upstream-name", "some-upstream-type"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantErr: `unable to find upstream identity provider with name "INVALID-upstream-name" and type "some-upstream-type". Found these providers: ` +
				stringVersionOfSomeIDPDiscoveryResponseIDPs,
		},
		{
			name: "when the Supervisor does not have an IDP that matches by type, return an error",
			options: []Option{
				WithUpstreamIdentityProvider("some-upstream-name", "other-supported-type-with-no-idp"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantErr: `unable to find upstream identity provider with name "some-upstream-name" and type "other-supported-type-with-no-idp". Found these providers: ` +
				stringVersionOfSomeIDPDiscoveryResponseIDPs,
		},
		{
			name: "when the Supervisor does not have an IDP that matches by flow, return an error",
			options: []Option{
				WithUpstreamIdentityProvider("idp-name-with-no-flows", "idp-type-with-no-flows"),
				WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode, "flowSource"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantErr: `unable to find upstream identity provider with name "idp-name-with-no-flows" and type "idp-type-with-no-flows" and flow "browser_authcode". Found these providers: ` +
				stringVersionOfSomeIDPDiscoveryResponseIDPs,
		},
		{
			name: "with IDP name and type, without IDP flow, when the Supervisor says that IDP has no flows, return an error",
			options: []Option{
				WithUpstreamIdentityProvider("idp-name-with-no-flows", "idp-type-with-no-flows"),
				withIDPDiscovery(someIDPDiscoveryResponse),
			},
			wantErr: `unable to infer flow for upstream identity provider with name "idp-name-with-no-flows" and type "idp-type-with-no-flows" because there were no flows discovered for that provider`,
		},
		{
			name: "with IDP name, when issuer does not have Pinniped-style IDP discovery, return error",
			options: []Option{
				WithUpstreamIdentityProvider("some-upstream-name", "some-upstream-type"),
				withIssuer("https://fake-issuer.com"),
			},
			wantErr: `upstream identity provider name "some-upstream-name" was specified, but OIDC issuer "https://fake-issuer.com" does not offer Pinniped-style IDP discovery, so it does not appear to be a Pinniped Supervisor; specifying an upstream identity provider name is only meant to be used with Pinniped Supervisors`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var h handlerState

			for _, option := range test.options {
				require.NoError(t, option(&h))
			}

			actualLoginFlow, actualAuthCodeOptions, actualError := h.maybePerformPinnipedSupervisorValidations()

			if test.wantErr != "" {
				require.EqualError(t, actualError, test.wantErr)
				return
			}

			require.NoError(t, actualError)
			require.Equal(t, test.wantAuthCodeOptions, actualAuthCodeOptions)
			require.Equal(t, test.wantLoginFlow, actualLoginFlow)
		})
	}
}

func TestLoggers(t *testing.T) {
	t.Run("with deprecated logger and new logger, returns an error", func(t *testing.T) {
		token, err := Login("https://127.0.0.1", "clientID",
			WithLogger(logr.Discard()),
			WithLoginLogger(plog.New()),
		)
		require.EqualError(t, err, "please use only one mechanism to specify the logger")
		require.Nil(t, token)
	})

	issuer, _ := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "some discovery error", http.StatusInternalServerError)
	}), nil)

	t.Run("with new logger, outputs logs", func(t *testing.T) {
		logger, log := plog.TestLogger(t)

		token, err := Login(issuer.URL, "clientID",
			WithLoginLogger(logger),
		)
		// This error is expected, we're testing logs not discovery
		require.EqualError(t, err, `could not perform OIDC discovery for "`+issuer.URL+`": Get "`+issuer.URL+`/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
		require.Nil(t, token)

		wantLog := `{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"oidcclient/login.go:<line>$oidcclient.(*handlerState).initOIDCDiscovery","message":"Pinniped: Performing OIDC discovery","issuer":"` + issuer.URL + `"}`
		require.Equal(t, wantLog+"\n", log.String())
	})

	t.Run("with deprecated logger, outputs logs", func(t *testing.T) {
		testLog := testlogger.NewLegacy(t) //nolint:staticcheck // This is specifically meant to test deprecated code
		token, err := Login(issuer.URL, "clientID",
			WithLogger(testLog.Logger),
		)
		// This error is expected, we're testing logs not discovery
		require.EqualError(t, err, `could not perform OIDC discovery for "`+issuer.URL+`": Get "`+issuer.URL+`/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
		require.Nil(t, token)

		wantLogs := []string{
			`"level"=4 "msg"="Pinniped: Performing OIDC discovery"  "issuer"="` + issuer.URL + `"`,
		}
		require.Equal(t, wantLogs, testLog.Lines())
	})

	// NOTE: We can't really test logs with the default (e.g. no logger option specified)
}

func TestMaybePrintAuditID(t *testing.T) {
	canonicalAuditIdHeaderName := "Audit-Id"

	buildResponse := func(statusCode int) *http.Response {
		return &http.Response{
			Header: http.Header{
				canonicalAuditIdHeaderName: []string{"some-audit-id", "some-other-audit-id-that-will-never-be-seen"},
			},
			StatusCode: statusCode,
			Request: &http.Request{
				URL: &url.URL{
					Path: "some-path-from-response-request",
				},
			},
		}
	}
	tests := []struct {
		name        string
		response    *http.Response
		responseErr error
		want        func(t *testing.T, called func()) auditIDLoggerFunc
		wantCalled  bool
	}{
		{
			name:        "happy HTTP response - no error",
			response:    buildResponse(http.StatusOK), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(_ string, _ int, _ string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name: "HTTP response with no response.request.url will not log",
			response: func() *http.Response {
				response := buildResponse(http.StatusOK)
				response.Request.URL = nil
				return response
			}(), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(_ string, _ int, _ string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name: "302 with error parameter in location and audit-ID will log",
			response: func() *http.Response {
				response := buildResponse(http.StatusFound)
				response.Header.Set("Location", "https://example.com?error=some-error")
				return response
			}(), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
					require.Equal(t, "some-path-from-response-request", path)
					require.Equal(t, http.StatusFound, statusCode)
					require.Equal(t, "some-audit-id", auditID)
				}
			},
			wantCalled: true,
		},
		{
			name: "303 with error parameter in location and audit-ID will log",
			response: func() *http.Response {
				response := buildResponse(http.StatusSeeOther)
				response.Header.Set("Location", "https://example.com?error=some-error")
				return response
			}(), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
					require.Equal(t, "some-path-from-response-request", path)
					require.Equal(t, http.StatusSeeOther, statusCode)
					require.Equal(t, "some-audit-id", auditID)
				}
			},
			wantCalled: true,
		},
		{
			name: "303 without error parameter in location and audit-ID will not log",
			response: func() *http.Response {
				response := buildResponse(http.StatusSeeOther)
				response.Header.Set("Location", "https://example.com?foo=bar")
				return response
			}(), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name:        "404 with error parameter in location and audit-ID will log",
			response:    buildResponse(http.StatusNotFound), //nolint:bodyclose // there is no Body.
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
					require.Equal(t, "some-path-from-response-request", path)
					require.Equal(t, http.StatusNotFound, statusCode)
					require.Equal(t, "some-audit-id", auditID)
				}
			},
			wantCalled: true,
		},
		{
			name:        "when the roundtrip returns an error, will not log",
			responseErr: errors.New("some error"),
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotNil(t, test.want)

			mockRequest := &http.Request{
				URL: &url.URL{
					Path: "should-never-use-this-path",
				},
			}
			var mockRt roundtripper.Func = func(r *http.Request) (*http.Response, error) {
				require.Equal(t, mockRequest, r)
				return test.response, test.responseErr
			}
			called := false
			subjectRt := maybePrintAuditID(mockRt, test.want(t, func() {
				called = true
			}))
			actualResponse, err := subjectRt.RoundTrip(mockRequest) //nolint:bodyclose // there is no Body.
			require.Equal(t, test.responseErr, err)                 // This roundtripper only returns mocked errors.
			require.Equal(t, test.response, actualResponse)
			require.Equal(t, test.wantCalled, called, "expected logFunc to be called")
		})
	}
}
