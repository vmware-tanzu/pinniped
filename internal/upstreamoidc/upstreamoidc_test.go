// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/mocks/mockkeyset"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/nonce"
)

func TestProviderConfig(t *testing.T) {
	t.Run("getters get", func(t *testing.T) {
		p := ProviderConfig{
			Name:          "test-name",
			UsernameClaim: "test-username-claim",
			GroupsClaim:   "test-groups-claim",
			Config: &oauth2.Config{
				ClientID: "test-client-id",
				Endpoint: oauth2.Endpoint{AuthURL: "https://example.com"},
				Scopes:   []string{"scope1", "scope2"},
			},
		}
		require.Equal(t, "test-name", p.GetName())
		require.Equal(t, "test-client-id", p.GetClientID())
		require.Equal(t, "https://example.com", p.GetAuthorizationURL().String())
		require.ElementsMatch(t, []string{"scope1", "scope2"}, p.GetScopes())
		require.Equal(t, "test-username-claim", p.GetUsernameClaim())
		require.Equal(t, "test-groups-claim", p.GetGroupsClaim())
	})

	const (
		// Test JWTs generated with https://smallstep.com/docs/cli/crypto/jwt/:

		// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"at_hash": "invalid-at-hash"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
		invalidAccessTokenHashIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdF9oYXNoIjoiaW52YWxpZC1hdC1oYXNoIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE2MDIyODM3OTEsImp0aSI6InRlc3QtanRpIiwibmJmIjoxNjAyMjgzNzkxLCJzdWIiOiJ0ZXN0LXVzZXIifQ.jryXr4jiwcf79wBLaHpjdclEYHoUFGhvTu95QyA6Hnk9NQ0x1vsWYurtj7a8uKydNPryC_HNZi9QTAE_tRIJjycseog3695-5y4B4EZlqL-a94rdOtffuF2O_lnPbKvoja9EKNrp0kLBCftFRHhLAEwuP0N9E5padZwPpIGK0yE_JqljnYgCySvzsQu7tasR38yaULny13h3mtp2WRHPG5DrLyuBuF8Z01hSgRi5hGcVpgzTwBgV5-eMaSUCUo-ZDkqUsLQI6dVlaikCSKYZRb53HeexH0tB_R9PJJHY7mIr-rS76kkQEx9pLuVnheIH9Oc6zbdYWg-zWMijopA8Pg" //nolint: gosec

		// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"nonce": "invalid-nonce"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
		invalidNonceIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTYwMjI4Mzc0MSwianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MDIyODM3NDEsIm5vbmNlIjoiaW52YWxpZC1ub25jZSIsInN1YiI6InRlc3QtdXNlciJ9.PRpq-7j5djaIAkraL-8t8ad9Xm4hM8RW67gyD1VIe0BecWeBFxsTuh3SZVKM9zmcwTgjudsyn8kQOwipDa49IN4PV8FcJA_uUJZi2wiqGJUSTG2K5I89doV_7e0RM1ZYIDDW1G2heKJNW7MbKkX7iEPr7u4MyEzswcPcupbyDA-CQFeL95vgwawoqa6yO94ympTbozqiNfj6Xyw_nHtThQnstjWsJZ9s2mUgppZezZv4HZYTQ7c3e_bzwhWgCzh2CSDJn9_Ra_n_4GcVkpHbsHTP35dFsnf0vactPx6CAu6A1-Apk-BruCktpZ3B4Ercf1UnUOHdGqzQKJtqvB03xQ" //nolint: gosec

		// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"foo": "bar", "bat": "baz"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
		validIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImJhdCI6ImJheiIsImZvbyI6ImJhciIsImlhdCI6MTYwNjc2ODU5MywianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MDY3Njg1OTMsInN1YiI6InRlc3QtdXNlciJ9.DuqVZ7pGhHqKz7gNr4j2W1s1N8YrSltktH4wW19L4oD1OE2-O72jAnNj5xdjilsa8l7h9ox-5sMF0Tkh3BdRlHQK9dEtNm9tW-JreUnWJ3LCqUs-LZp4NG7edvq2sH_1Bn7O2_NQV51s8Pl04F60CndjQ4NM-6WkqDQTKyY6vJXU7idvM-6TM2HJZK-Na88cOJ9KIK37tL5DhcbsHVF47Dq8uPZ0KbjNQjJLAIi_1GeQBgc6yJhDUwRY4Xu6S0dtTHA6xTI8oSXoamt4bkViEHfJBp97LZQiNz8mku5pVc0aNwP1p4hMHxRHhLXrJjbh-Hx4YFjxtOnIq9t1mHlD4A" //nolint: gosec
	)

	tests := []struct {
		name        string
		authCode    string
		expectNonce nonce.Nonce
		returnIDTok string
		wantErr     string
		wantToken   oidcclient.Token
		wantClaims  map[string]interface{}
	}{
		{
			name:     "exchange fails with network error",
			authCode: "invalid-auth-code",
			wantErr:  "oauth2: cannot fetch token: 403 Forbidden\nResponse: invalid authorization code\n",
		},
		{
			name:     "missing ID token",
			authCode: "valid",
			wantErr:  "received response missing ID token",
		},
		{
			name:        "invalid ID token",
			authCode:    "valid",
			returnIDTok: "invalid-jwt",
			wantErr:     "received invalid ID token: oidc: malformed jwt: square/go-jose: compact JWS format must have three parts",
		},
		{
			name:        "invalid access token hash",
			authCode:    "valid",
			returnIDTok: invalidAccessTokenHashIDToken,
			wantErr:     "received invalid ID token: access token hash does not match value in ID token",
		},
		{
			name:        "invalid nonce",
			authCode:    "valid",
			expectNonce: "test-nonce",
			returnIDTok: invalidNonceIDToken,
			wantErr:     `received ID token with invalid nonce: invalid nonce (expected "test-nonce", got "invalid-nonce")`,
		},
		{
			name:        "invalid nonce but not checked",
			authCode:    "valid",
			expectNonce: "",
			returnIDTok: invalidNonceIDToken,
			wantToken: oidcclient.Token{
				AccessToken: &oidcclient.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidcclient.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidcclient.IDToken{
					Token:  invalidNonceIDToken,
					Expiry: metav1.Time{},
				},
			},
		},
		{
			name:        "valid",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantToken: oidcclient.Token{
				AccessToken: &oidcclient.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidcclient.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidcclient.IDToken{
					Token:  validIDToken,
					Expiry: metav1.Time{},
				},
			},
			wantClaims: map[string]interface{}{
				"foo": "bar",
				"bat": "baz",
			},
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
				response.RefreshToken = "test-refresh-token"
				response.Expiry = time.Now().Add(time.Hour)
				response.IDToken = tt.returnIDTok
				w.Header().Set("content-type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(&response))
			}))
			t.Cleanup(tokenServer.Close)

			p := ProviderConfig{
				Name:          "test-name",
				UsernameClaim: "test-username-claim",
				GroupsClaim:   "test-groups-claim",
				Config: &oauth2.Config{
					ClientID: "test-client-id",
					Endpoint: oauth2.Endpoint{
						AuthURL:   "https://example.com",
						TokenURL:  tokenServer.URL,
						AuthStyle: oauth2.AuthStyleInParams,
					},
					Scopes: []string{"scope1", "scope2"},
				},
				Provider: &mockProvider{},
			}

			ctx := context.Background()

			tok, claims, err := p.ExchangeAuthcodeAndValidateTokens(ctx, tt.authCode, "test-pkce", tt.expectNonce)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Equal(t, oidcclient.Token{}, tok)
				require.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantToken, tok)

			for k, v := range tt.wantClaims {
				require.Equal(t, v, claims[k])
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

type mockProvider struct{}

func (m *mockProvider) Verifier(_ *oidc.Config) *oidc.IDTokenVerifier { return mockVerifier() }
