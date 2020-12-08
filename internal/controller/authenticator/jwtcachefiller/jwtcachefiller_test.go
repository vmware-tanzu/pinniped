// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/mocks/mocktokenauthenticatorcloser"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		cache             func(*authncache.Cache)
		syncKey           controllerlib.Key
		jwtAuthenticators []runtime.Object
		wantErr           string
		wantLogs          []string
		wantCacheEntries  int
	}{
		{
			name:    "not found",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="Sync() found that the JWTAuthenticator does not exist yet or was deleted"`,
			},
		},
		{
			name:    "valid jwt authenticator with CA",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: auth1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://some-issuer.com",
						Audience: "some-audience",
						TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"},
					},
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="https://some-issuer.com" "jwtAuthenticator"={"name":"test-name","namespace":"test-namespace"}`,
			},
			wantCacheEntries: 1,
		},
		{
			name: "updating jwt authenticator closes previous instance",
			cache: func(cache *authncache.Cache) {
				cache.Store(
					authncache.Key{
						Name:      "test-name",
						Namespace: "test-namespace",
						Kind:      "JWTAuthenticator",
						APIGroup:  auth1alpha1.SchemeGroupVersion.Group,
					},
					newClosableCacheValue(t, 1),
				)
			},
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: auth1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://some-issuer.com",
						Audience: "some-audience",
						TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"},
					},
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="https://some-issuer.com" "jwtAuthenticator"={"name":"test-name","namespace":"test-namespace"}`,
			},
			wantCacheEntries: 1,
		},
		{
			name:    "valid jwt authenticator without CA",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: auth1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://some-issuer.com",
						Audience: "some-audience",
					},
				},
			},
			wantLogs: []string{
				`jwtcachefiller-controller "level"=0 "msg"="added new jwt authenticator" "issuer"="https://some-issuer.com" "jwtAuthenticator"={"name":"test-name","namespace":"test-namespace"}`,
			},
			wantCacheEntries: 1,
		},
		{
			name:    "invalid jwt authenticator CA",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: auth1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://some-issuer.com",
						Audience: "some-audience",
						TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "not base64-encoded"},
					},
				},
			},
			wantErr: "failed to build jwt authenticator: invalid TLS configuration: illegal base64 data at input byte 3",
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
				tt.cache(cache)
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
		})
	}
}

func TestNewJWTAuthenticator(t *testing.T) {
	t.Parallel()

	const (
		goodSubject  = "some-subject"
		goodAudience = "some-audience"
		group0       = "some-group-0"
		group1       = "some-group-1"

		goodECSigningKeyID  = "some-ec-key-id"
		goodRSASigningKeyID = "some-rsa-key-id"
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
	a, err := newJWTAuthenticator(&auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(server.TLS),
	})
	require.NoError(t, err)
	t.Cleanup(a.Close)

	// The implementation of AuthenticateToken() that we use waits 10 seconds after creation to
	// perform OIDC discovery. Therefore, the JWTAuthenticator is not functional for the first 10
	// seconds. We sleep for 13 seconds in this unit test to give a little bit of cushion to that 10
	// second delay.
	//
	// We should get rid of this 10 second delay. See
	// https://github.com/vmware-tanzu/pinniped/issues/260.
	if testing.Short() {
		t.Skip("skipping this test when '-short' flag is passed to avoid necessary 13 second sleep")
	}
	time.Sleep(time.Second * 13)

	var tests = []struct {
		name              string
		jwtClaims         func(wellKnownClaims *jwt.Claims, groups *interface{})
		jwtSignature      func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string)
		wantResponse      *authenticator.Response
		wantAuthenticated bool
		wantErrorRegexp   string
	}{
		{
			name: "good token without groups and with EC signature",
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name: goodSubject,
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
					Name: goodSubject,
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with groups as array",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}) {
				*groups = []string{group0, group1}
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   goodSubject,
					Groups: []string{group0, group1},
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with groups as string",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}) {
				*groups = group0
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   goodSubject,
					Groups: []string{group0},
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "good token with nbf unset",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.NotBefore = nil
			},
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name: goodSubject,
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "bad token with groups as map",
			jwtClaims: func(_ *jwt.Claims, groups *interface{}) {
				*groups = map[string]string{"not an array": "or a string"}
			},
			wantErrorRegexp: "oidc: parse groups claim \"groups\": json: cannot unmarshal object into Go value of type string",
		},
		{
			name: "bad token with wrong issuer",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.Issuer = "wrong-issuer"
			},
			wantResponse:      nil,
			wantAuthenticated: false,
		},
		{
			name: "bad token with no audience",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.Audience = nil
			},
			wantErrorRegexp: `oidc: verify token: oidc: expected audience "some-audience" got \[\]`,
		},
		{
			name: "bad token with wrong audience",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.Audience = []string{"wrong-audience"}
			},
			wantErrorRegexp: `oidc: verify token: oidc: expected audience "some-audience" got \["wrong-audience"\]`,
		},
		{
			name: "bad token with nbf in the future",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.NotBefore = jwt.NewNumericDate(time.Date(3020, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErrorRegexp: `oidc: verify token: oidc: current time .* before the nbf \(not before\) time: 3020-.*`,
		},
		{
			name: "bad token with exp in past",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.Expiry = jwt.NewNumericDate(time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErrorRegexp: `oidc: verify token: oidc: token is expired \(Token Expiry: 0001-02-02 23:09:04 -0456 LMT\)`,
		},
		{
			name: "bad token without exp",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}) {
				claims.Expiry = nil
			},
			wantErrorRegexp: `oidc: verify token: oidc: token is expired \(Token Expiry: 0001-01-01 00:00:00 \+0000 UTC\)`,
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
	for _, test := range tests {
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
			if test.jwtClaims != nil {
				test.jwtClaims(&wellKnownClaims, &groups)
			}

			var signingKey interface{} = goodECSigningKey
			signingAlgo := goodECSigningAlgo
			signingKID := goodECSigningKeyID
			if test.jwtSignature != nil {
				test.jwtSignature(&signingKey, &signingAlgo, &signingKID)
			}

			jwt := createJWT(t, signingKey, signingAlgo, signingKID, &wellKnownClaims, groups)
			rsp, authenticated, err := a.AuthenticateToken(context.Background(), jwt)
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
	groups interface{},
) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signingAlgo, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	builder := jwt.Signed(sig).Claims(claims)
	if groups != nil {
		builder = builder.Claims(map[string]interface{}{"groups": groups})
	}
	jwt, err := builder.CompactSerialize()
	require.NoError(t, err)

	return jwt
}

func newClosableCacheValue(t *testing.T, wantCloses int) authncache.Value {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	tac := mocktokenauthenticatorcloser.NewMockTokenAuthenticatorCloser(ctrl)
	tac.EXPECT().Close().Times(wantCloses)
	return tac
}
