// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwtcachefiller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/mocks/mocktokenauthenticatorcloser"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	const (
		goodECSigningKeyID  = "some-ec-key-id"
		goodRSASigningKeyID = "some-rsa-key-id"
		goodAudience        = "some-audience"
	)

	goodECSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	goodECSigningAlgo := jose.ES256
	require.NoError(t, err)

	goodRSASigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	goodRSASigningAlgo := jose.RS256

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	mux.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, server.URL, server.URL+"/jwks.json")
		require.NoError(t, err)
	}))
	mux.Handle("/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ecJWK := jose.JSONWebKey{
			Key:       goodECSigningKey,
			KeyID:     goodECSigningKeyID,
			Algorithm: string(goodECSigningAlgo),
			Use:       "sig",
		}
		rsaJWK := jose.JSONWebKey{
			Key:       goodRSASigningKey,
			KeyID:     goodRSASigningKeyID,
			Algorithm: string(goodRSASigningAlgo),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{ecJWK.Public(), rsaJWK.Public()},
		}
		require.NoError(t, json.NewEncoder(w).Encode(jwks))
	}))

	goodIssuer := server.URL

	someJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(server.TLS),
	}
	someJWTAuthenticatorSpecWithUsernameClaim := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(server.TLS),
		Claims: auth1alpha1.JWTTokenClaims{
			Username: "my-custom-username-claim",
		},
	}
	someJWTAuthenticatorSpecWithGroupsClaim := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(server.TLS),
		Claims: auth1alpha1.JWTTokenClaims{
			Groups: "my-custom-groups-claim",
		},
	}
	otherJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   "https://some-other-issuer.com",
		Audience: goodAudience,
		TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"},
	}
	missingTLSJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
	}
	invalidTLSJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   "https://some-other-issuer.com",
		Audience: goodAudience,
		TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "invalid base64-encoded data"},
	}

	tests := []struct {
		name                             string
		cache                            func(*testing.T, *authncache.Cache, bool)
		syncKey                          controllerlib.Key
		jwtAuthenticators                []runtime.Object
		wantClose                        bool
		wantErr                          string
		wantLogs                         []string
		wantCacheEntries                 int
		wantUsernameClaim                string
		wantGroupsClaim                  string
		runTestsOnResultingAuthenticator bool
	}{
		{
			name:    "not found",
			syncKey: controllerlib.Key{Name: "test-name"},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="Sync() found that the JWTAuthenticator does not exist yet or was deleted"`,
			},
		},
		{
			name:    "valid jwt authenticator with CA",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "valid jwt authenticator with custom username claim",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithUsernameClaim,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			wantUsernameClaim:                someJWTAuthenticatorSpecWithUsernameClaim.Claims.Username,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "valid jwt authenticator with custom groups claim",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithGroupsClaim,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			wantGroupsClaim:                  someJWTAuthenticatorSpecWithGroupsClaim.Claims.Groups,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name: "updating jwt authenticator with new fields closes previous instance",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: auth1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *otherJWTAuthenticatorSpec, wantClose),
				)
			},
			wantClose: true,
			syncKey:   controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name: "updating jwt authenticator with the same value does nothing",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: auth1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *someJWTAuthenticatorSpec, wantClose),
				)
			},
			wantClose: false,
			syncKey:   controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="actual jwt authenticator and desired jwt authenticator are the same" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: false, // skip the tests because the authenticator left in the cache is the mock version that was added above
		},
		{
			name: "updating jwt authenticator when cache value is wrong type",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: auth1alpha1.SchemeGroupVersion.Group,
					},
					struct{ authenticator.Token }{},
				)
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="wrong JWT authenticator type in cache" "actualType"="struct { authenticator.Token }"`,
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "valid jwt authenticator without CA",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *missingTLSJWTAuthenticatorSpec,
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="` + goodIssuer + `" "jwtAuthenticator"={"name":"test-name"}`,
			},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: false, // skip the tests because the authenticator left in the cache doesn't have the CA for our test discovery server
		},
		{
			name:    "invalid jwt authenticator CA",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
				},
			},
			wantErr: "failed to build jwt authenticator: invalid TLS configuration: illegal base64 data at input byte 7",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := pinnipedfake.NewSimpleClientset(tt.jwtAuthenticators...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := authncache.New()
			testLog := testlogger.New(t)

			if tt.cache != nil {
				tt.cache(t, cache, tt.wantClose)
			}

			controller := New(cache, informers.Authentication().V1alpha1().JWTAuthenticators(), testLog)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantLogs, testLog.Lines())
			require.Equal(t, tt.wantCacheEntries, len(cache.Keys()))

			if !tt.runTestsOnResultingAuthenticator {
				return // end of test unless we wanted to run tests on the resulting authenticator from the cache
			}

			// The implementation of AuthenticateToken() that we use waits 10 seconds after creation to
			// perform OIDC discovery. Therefore, the JWTAuthenticator is not functional for the first 10
			// seconds. We sleep for 13 seconds in this unit test to give a little bit of cushion to that 10
			// second delay.
			//
			// We should get rid of this 10 second delay. See
			// https://github.com/vmware-tanzu/pinniped/issues/260.
			time.Sleep(time.Second * 13)

			// We expected the cache to have an entry, so pull that entry from the cache and test it.
			expectedCacheKey := authncache.Key{
				APIGroup: auth1alpha1.GroupName,
				Kind:     "JWTAuthenticator",
				Name:     syncCtx.Key.Name,
			}
			cachedAuthenticator := cache.Get(expectedCacheKey)
			require.NotNil(t, cachedAuthenticator)

			// Schedule it to be closed at the end of the test.
			t.Cleanup(cachedAuthenticator.(*jwtAuthenticator).Close)

			const (
				goodSubject  = "some-subject"
				group0       = "some-group-0"
				group1       = "some-group-1"
				goodUsername = "pinny123"
			)

			if tt.wantUsernameClaim == "" {
				tt.wantUsernameClaim = "username"
			}

			if tt.wantGroupsClaim == "" {
				tt.wantGroupsClaim = "groups"
			}

			for _, test := range testTableForAuthenticateTokenTests(
				t,
				goodRSASigningKey,
				goodRSASigningAlgo,
				goodRSASigningKeyID,
				group0,
				group1,
				goodUsername,
				tt.wantUsernameClaim,
				tt.wantGroupsClaim,
			) {
				test := test
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()

					wellKnownClaims := jwt.Claims{
						Issuer:    goodIssuer,
						Subject:   goodSubject,
						Audience:  []string{goodAudience},
						Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					}
					var groups interface{}
					username := goodUsername
					if test.jwtClaims != nil {
						test.jwtClaims(&wellKnownClaims, &groups, &username)
					}

					var signingKey interface{} = goodECSigningKey
					signingAlgo := goodECSigningAlgo
					signingKID := goodECSigningKeyID
					if test.jwtSignature != nil {
						test.jwtSignature(&signingKey, &signingAlgo, &signingKID)
					}

					jwt := createJWT(
						t,
						signingKey,
						signingAlgo,
						signingKID,
						&wellKnownClaims,
						tt.wantGroupsClaim,
						groups,
						tt.wantUsernameClaim,
						username,
					)
					rsp, authenticated, err := cachedAuthenticator.AuthenticateToken(context.Background(), jwt)
					if test.wantErrorRegexp != "" {
						require.Error(t, err)
						require.Regexp(t, test.wantErrorRegexp, err.Error())
					} else {
						require.NoError(t, err)
						require.Equal(t, test.wantResponse, rsp)
						require.Equal(t, test.wantAuthenticated, authenticated)
					}
				})
			}
		})
	}
}

func testTableForAuthenticateTokenTests(
	t *testing.T,
	goodRSASigningKey *rsa.PrivateKey,
	goodRSASigningAlgo jose.SignatureAlgorithm,
	goodRSASigningKeyID string,
	group0 string,
	group1 string,
	goodUsername string,
	expectedUsernameClaim string,
	expectedGroupsClaim string,
) []struct {
	name              string
	jwtClaims         func(wellKnownClaims *jwt.Claims, groups *interface{}, username *string)
	jwtSignature      func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string)
	wantResponse      *authenticator.Response
	wantAuthenticated bool
	wantErrorRegexp   string
} {
	tests := []struct {
		name              string
		jwtClaims         func(wellKnownClaims *jwt.Claims, groups *interface{}, username *string)
		jwtSignature      func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string)
		wantResponse      *authenticator.Response
		wantAuthenticated bool
		wantErrorRegexp   string
	}{
		{
			name: "good token without groups and with EC signature",
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name: goodUsername,
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token without groups and with RSA signature",
			jwtSignature: func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string) {
				*key = goodRSASigningKey
				*algo = goodRSASigningAlgo
				*kid = goodRSASigningKeyID
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name: goodUsername,
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with groups as array",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}, username *string) {
				*groups = []string{group0, group1}
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   goodUsername,
					Groups: []string{group0, group1},
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with groups as string",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}, username *string) {
				*groups = group0
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   goodUsername,
					Groups: []string{group0},
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with nbf unset",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.NotBefore = nil
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name: goodUsername,
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "bad token with groups as map",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}, username *string) {
				*groups = map[string]string{"not an array": "or a string"}
			},
			wantErrorRegexp: "oidc: parse groups claim \"" + expectedGroupsClaim + "\": json: cannot unmarshal object into Go value of type string",
		},
		{
			name: "bad token with wrong issuer",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Issuer = "wrong-issuer"
			},
			wantResponse:      nil,
			wantAuthenticated: false,
		},
		{
			name: "bad token with no audience",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Audience = nil
			},
			wantErrorRegexp: `oidc: verify token: oidc: expected audience "some-audience" got \[\]`,
		},
		{
			name: "bad token with wrong audience",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Audience = []string{"wrong-audience"}
			},
			wantErrorRegexp: `oidc: verify token: oidc: expected audience "some-audience" got \["wrong-audience"\]`,
		},
		{
			name: "bad token with nbf in the future",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.NotBefore = jwt.NewNumericDate(time.Date(3020, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErrorRegexp: `oidc: verify token: oidc: current time .* before the nbf \(not before\) time: 3020-.*`,
		},
		{
			name: "bad token with exp in past",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Expiry = jwt.NewNumericDate(time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErrorRegexp: `oidc: verify token: oidc: token is expired \(Token Expiry: .+`,
		},
		{
			name: "bad token without exp",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Expiry = nil
			},
			wantErrorRegexp: `oidc: verify token: oidc: token is expired \(Token Expiry: .+`,
		},
		{
			name: "token does not have username claim",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				*username = ""
			},
			wantErrorRegexp: `oidc: parse username claims "` + expectedUsernameClaim + `": claim not present`,
		},
		{
			name: "signing key is wrong",
			jwtSignature: func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string) {
				var err error
				*key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				*algo = jose.ES256
			},
			wantErrorRegexp: `oidc: verify token: failed to verify signature: failed to verify id token signature`,
		},
		{
			name: "signing algo is unsupported",
			jwtSignature: func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string) {
				var err error
				*key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				*algo = jose.ES384
			},
			wantErrorRegexp: `oidc: verify token: oidc: id token signed with unsupported algorithm, expected \["RS256" "ES256"\] got "ES384"`,
		},
	}

	return tests
}

func tlsSpecFromTLSConfig(tls *tls.Config) *auth1alpha1.TLSSpec {
	pemData := make([]byte, 0)
	for _, certificate := range tls.Certificates {
		for _, reallyCertificate := range certificate.Certificate {
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: reallyCertificate,
			})...)
		}
	}
	return &auth1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(pemData),
	}
}

func createJWT(
	t *testing.T,
	signingKey interface{},
	signingAlgo jose.SignatureAlgorithm,
	kid string,
	claims *jwt.Claims,
	groupsClaim string,
	groupsValue interface{},
	usernameClaim string,
	usernameValue string,
) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signingAlgo, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	builder := jwt.Signed(sig).Claims(claims)
	if groupsValue != nil {
		builder = builder.Claims(map[string]interface{}{groupsClaim: groupsValue})
	}
	if usernameValue != "" {
		builder = builder.Claims(map[string]interface{}{usernameClaim: usernameValue})
	}
	jwt, err := builder.CompactSerialize()
	require.NoError(t, err)

	return jwt
}

func newCacheValue(t *testing.T, spec auth1alpha1.JWTAuthenticatorSpec, wantClose bool) authncache.Value {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	tokenAuthenticatorCloser := mocktokenauthenticatorcloser.NewMockTokenAuthenticatorCloser(ctrl)

	wantCloses := 0
	if wantClose {
		wantCloses++
	}
	tokenAuthenticatorCloser.EXPECT().Close().Times(wantCloses)

	return &jwtAuthenticator{
		tokenAuthenticatorCloser: tokenAuthenticatorCloser,
		spec:                     &spec,
	}
}
