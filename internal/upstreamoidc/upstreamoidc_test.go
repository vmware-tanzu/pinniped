// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/mocks/mockkeyset"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
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

		// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"foo": "bar", "bat": "baz"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub '' --subtle --kid="test-kid" --jti="test-jti"
		invalidSubClaim = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImJhdCI6ImJheiIsImZvbyI6ImJhciIsImlhdCI6MTYxMDIxOTY5MCwianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MTAyMTk2OTB9.CXgUarh9A8QByF_ddw0W1Cldl_n1qmry2cZh9U0Avi5sl7hb1y22MadDLQslvnx0NKx6EdbwI-El7QxDy0SzwomJomFL7WNd5gGk-Ilq9O_emaHekbpphZ5kxyudsAGUYGxrg1zysv1k5JPhnLnOUMcE7wa0uPLDWnrlAMzqHvnbjI3lakZ8v4-dfAKUIUGi3ycwuAh9BdpydwAsSNOpGBM55-O8911dqVfZKiFNNUeHYE1qlnbhCz7_ykLrljao0nRBbEf9FXGolCdhIaglt0LtaZvll9T9StIbSpcRaBGuRm8toTezmhmHjU-iCc0jGeVKsp8eTyOuJllqDSS-uw"

		// step crypto keypair key.pub key.priv --kty RSA --no-password --insecure --force && echo '{"foo": "bar", "bat": "baz"}' | step crypto jwt sign --key key.priv --aud test-client-id --sub test-user --subtle --kid="test-kid" --jti="test-jti"
		validIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0LWNsaWVudC1pZCIsImJhdCI6ImJheiIsImZvbyI6ImJhciIsImlhdCI6MTYwNjc2ODU5MywianRpIjoidGVzdC1qdGkiLCJuYmYiOjE2MDY3Njg1OTMsInN1YiI6InRlc3QtdXNlciJ9.DuqVZ7pGhHqKz7gNr4j2W1s1N8YrSltktH4wW19L4oD1OE2-O72jAnNj5xdjilsa8l7h9ox-5sMF0Tkh3BdRlHQK9dEtNm9tW-JreUnWJ3LCqUs-LZp4NG7edvq2sH_1Bn7O2_NQV51s8Pl04F60CndjQ4NM-6WkqDQTKyY6vJXU7idvM-6TM2HJZK-Na88cOJ9KIK37tL5DhcbsHVF47Dq8uPZ0KbjNQjJLAIi_1GeQBgc6yJhDUwRY4Xu6S0dtTHA6xTI8oSXoamt4bkViEHfJBp97LZQiNz8mku5pVc0aNwP1p4hMHxRHhLXrJjbh-Hx4YFjxtOnIq9t1mHlD4A" //nolint: gosec
	)

	// if the error string for unsupported user info changes, this will hopefully catch it
	_, userInfoNotSupported := (&oidc.Provider{}).UserInfo(context.Background(), nil)

	tests := []struct {
		name        string
		authCode    string
		expectNonce nonce.Nonce
		returnIDTok string
		wantErr     string
		wantToken   oidctypes.Token

		userInfo           *oidc.UserInfo
		userInfoErr        error
		wantUserInfoCalled bool
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
			wantToken: oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidctypes.IDToken{
					Token:  invalidNonceIDToken,
					Expiry: metav1.Time{},
					Claims: map[string]interface{}{
						"aud":   "test-client-id",
						"iat":   1.602283741e+09,
						"jti":   "test-jti",
						"nbf":   1.602283741e+09,
						"nonce": "invalid-nonce",
						"sub":   "test-user",
					},
				},
			},
			userInfoErr:        userInfoNotSupported,
			wantUserInfoCalled: true,
		},
		{
			name:        "valid",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantToken: oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidctypes.IDToken{
					Token:  validIDToken,
					Expiry: metav1.Time{},
					Claims: map[string]interface{}{
						"foo": "bar",
						"bat": "baz",
						"aud": "test-client-id",
						"iat": 1.606768593e+09,
						"jti": "test-jti",
						"nbf": 1.606768593e+09,
						"sub": "test-user",
					},
				},
			},
			userInfoErr:        userInfoNotSupported,
			wantUserInfoCalled: true,
		},
		{
			name:        "user info fetch error",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantErr:     "could not fetch user info claims: could not get user info: some network error",
			userInfoErr: errors.New("some network error"),
		},
		{
			name:        "user info sub error",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantErr:     "could not fetch user info claims: userinfo 'sub' claim (test-user-2) did not match id_token 'sub' claim (test-user)",
			userInfo:    &oidc.UserInfo{Subject: "test-user-2"},
		},
		{
			name:        "user info is not json",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantErr:     "could not fetch user info claims: could not unmarshal user info claims: invalid character 'i' looking for beginning of value",
			// claims is private field so we have to use hacks to set it
			userInfo: forceUserInfoWithClaims("test-user", `invalid-json-data`),
		},
		{
			name:        "valid with user info",
			authCode:    "valid",
			returnIDTok: validIDToken,
			wantToken: oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidctypes.IDToken{
					Token:  validIDToken,
					Expiry: metav1.Time{},
					Claims: map[string]interface{}{
						"foo":    "awesomeness", // overwrite existing claim
						"bat":    "baz",
						"aud":    "test-client-id",
						"iat":    1.606768593e+09,
						"jti":    "test-jti",
						"nbf":    1.606768593e+09,
						"sub":    "test-user",
						"groups": "fancy-group", // add a new claim
					},
				},
			},
			// claims is private field so we have to use hacks to set it
			userInfo:           forceUserInfoWithClaims("test-user", `{"foo":"awesomeness","groups":"fancy-group"}`),
			wantUserInfoCalled: true,
		},
		{
			name:        "invalid sub claim",
			authCode:    "valid",
			returnIDTok: invalidSubClaim,
			wantToken: oidctypes.Token{
				AccessToken: &oidctypes.AccessToken{
					Token:  "test-access-token",
					Expiry: metav1.Time{},
				},
				RefreshToken: &oidctypes.RefreshToken{
					Token: "test-refresh-token",
				},
				IDToken: &oidctypes.IDToken{
					Token:  invalidSubClaim,
					Expiry: metav1.Time{},
					Claims: map[string]interface{}{
						"foo": "bar",
						"bat": "baz",
						"aud": "test-client-id",
						"iat": 1.61021969e+09,
						"jti": "test-jti",
						"nbf": 1.61021969e+09,
						// no sub claim
					},
				},
			},
			wantUserInfoCalled: false,
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
				Provider: &mockProvider{
					userInfo:    tt.userInfo,
					userInfoErr: tt.userInfoErr,
				},
			}

			ctx := context.Background()

			tok, err := p.ExchangeAuthcodeAndValidateTokens(ctx, tt.authCode, "test-pkce", tt.expectNonce, "https://example.com/callback")
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, tok)
				return
			}
			require.NoError(t, err)
			require.Equal(t, &tt.wantToken, tok)
			require.Equal(t, tt.wantUserInfoCalled, p.Provider.(*mockProvider).called)
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

type mockProvider struct {
	called      bool
	userInfo    *oidc.UserInfo
	userInfoErr error
}

func (m *mockProvider) Verifier(_ *oidc.Config) *oidc.IDTokenVerifier { return mockVerifier() }

func (m *mockProvider) UserInfo(_ context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	m.called = true

	token, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}
	if wantToken := "test-access-token"; wantToken != token.AccessToken {
		return nil, fmt.Errorf("want token = %#v, got token = %#v", wantToken, token)
	}

	return m.userInfo, m.userInfoErr
}

func forceUserInfoWithClaims(subject string, claims string) *oidc.UserInfo {
	userInfo := &oidc.UserInfo{Subject: subject}

	// this is some dark magic to set a private field
	claimsField := reflect.ValueOf(userInfo).Elem().FieldByName("claims")
	claimsPointer := (*[]byte)(unsafe.Pointer(claimsField.UnsafeAddr()))
	*claimsPointer = []byte(claims)

	return userInfo
}
