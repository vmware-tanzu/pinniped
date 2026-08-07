package oidcclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// テスト用の疑似 ID Token (JWT) を作成するヘルパー関数
func generateTestIDToken(issuer, audience, subject string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":%q,"sub":%q,"aud":%q,"exp":%d,"iat":%d}`,
		issuer, subject, audience, time.Now().Add(time.Hour).Unix(), time.Now().Unix(),
	)))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

func TestDeviceCodeBasedAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		setupServer    func(t *testing.T) *httptest.Server
		ctxTimeout     time.Duration
		wantErr        string
		wantIDTokenSub string
	}{
		{
			name: "success: device code flow completes after polling pending once",
			setupServer: func(t *testing.T) *httptest.Server {
				var pollCount int32
				var server *httptest.Server

				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/.well-known/openid-configuration":
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"issuer":                        server.URL,
							"authorization_endpoint":        server.URL + "/auth",
							"token_endpoint":                server.URL + "/token",
							"device_authorization_endpoint": server.URL + "/device/code",
							"jwks_uri":                      server.URL + "/jwks",
						})

					case "/device/code":
						require.Equal(t, http.MethodPost, r.Method)
						require.NoError(t, r.ParseForm())
						require.Equal(t, "test-client-id", r.Form.Get("client_id"))

						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(deviceAuthorizationResponse{
							DeviceCode:      "test-device-code",
							UserCode:        "ABCD-1234",
							VerificationURI: "https://example.com/device",
							ExpiresIn:       300,
							Interval:        1,
						})

					case "/token":
						require.Equal(t, http.MethodPost, r.Method)
						require.NoError(t, r.ParseForm())
						require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", r.Form.Get("grant_type"))
						require.Equal(t, "test-device-code", r.Form.Get("device_code"))

						count := atomic.AddInt32(&pollCount, 1)
						w.Header().Set("Content-Type", "application/json")

						if count == 1 {
							// 1回目は authorization_pending
							w.WriteHeader(http.StatusBadRequest)
							_ = json.NewEncoder(w).Encode(oauth2ErrorResponse{
								Error: "authorization_pending",
							})
							return
						}

						// 2回目で成功トークンを返す
						idToken := generateTestIDToken(server.URL, "test-client-id", "test-user-id")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"access_token":  "test-access-token",
							"token_type":    "Bearer",
							"id_token":      idToken,
							"refresh_token": "test-refresh-token",
							"expires_in":    3600,
						})

					default:
						http.NotFound(w, r)
					}
				}))
				return server
			},
			ctxTimeout:     5 * time.Second,
			wantIDTokenSub: "test-user-id",
		},
		{
			name: "error: missing device_authorization_endpoint in discovery",
			setupServer: func(t *testing.T) *httptest.Server {
				var server *httptest.Server
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/.well-known/openid-configuration" {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"issuer":                 server.URL,
							"authorization_endpoint": server.URL + "/auth",
							"token_endpoint":         server.URL + "/token",
						})
						return
					}
					http.NotFound(w, r)
				}))
				return server
			},
			ctxTimeout: 2 * time.Second,
			wantErr:    "issuer does not support device authorization grant",
		},
		{
			name: "error: access denied by user",
			setupServer: func(t *testing.T) *httptest.Server {
				var server *httptest.Server
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/.well-known/openid-configuration":
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"issuer":                        server.URL,
							"device_authorization_endpoint": server.URL + "/device/code",
							"token_endpoint":                server.URL + "/token",
						})
					case "/device/code":
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(deviceAuthorizationResponse{
							DeviceCode:      "test-device-code",
							UserCode:        "ABCD-1234",
							VerificationURI: "https://example.com/device",
							Interval:        1,
						})
					case "/token":
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(oauth2ErrorResponse{
							Error: "access_denied",
						})
					}
				}))
				return server
			},
			ctxTimeout: 3 * time.Second,
			wantErr:    "login access was denied by the user",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := tt.setupServer(t)
			defer server.Close()

			client := server.Client()
			ctx := oidc.ClientContext(context.Background(), client)
			ctx, cancel := context.WithTimeout(ctx, tt.ctxTimeout)
			defer cancel()

			provider, err := oidc.NewProvider(ctx, server.URL)
			require.NoError(t, err)

			out := &bytes.Buffer{}
			h := &handlerState{
				ctx:        ctx,
				clientID:   "test-client-id",
				provider:   provider,
				httpClient: client,
				oauth2Config: &oauth2.Config{
					ClientID: "test-client-id",
					Endpoint: oauth2.Endpoint{
						TokenURL: server.URL + "/token",
					},
				},
				scopes: []string{"openid", "profile"},
				out:    out,
				validateIDToken: func(ctx context.Context, _ *oidc.Provider, audience string, token string) (*oidc.IDToken, error) {
					// 署名検証をスキップして JWT を正常パース
					verifier := provider.Verifier(&oidc.Config{
						InsecureSkipSignatureCheck: true,
						SkipClientIDCheck:          true,
						SkipExpiryCheck:            true,
						SkipIssuerCheck:            true,
					})
					return verifier.Verify(ctx, token)
				},
			}

			token, err := h.deviceCodeBasedAuth(nil)

			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)
				require.Equal(t, "test-access-token", token.AccessToken.Token)
				require.Equal(t, tt.wantIDTokenSub, token.IDToken.Claims["sub"])
				require.Contains(t, out.String(), "https://example.com/device")
				require.Contains(t, out.String(), "ABCD-1234")
			}
		})
	}
}
