// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwtcachefiller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sinformers "k8s.io/client-go/informers"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/mocks/mockcachevalue"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/conditionstestutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

// This private key was randomly generated and then used to sign a single JWT.
// That JWT is hardcoded as the constant minimalJWTToTriggerJWKSFetch.
// TestMinimalJWTToTriggerJWKSFetch below shows how that JWT was created.
// This JWT will be used for only one purpose: to trick coreos.RemoteKeySet
// into fetching a remote JWKS immediately. Because we expect that there is no
// OIDC provider in the world that uses this randomly generated signing key,
// then we can safely assume that this JWT should never successfully verify
// using the real JWKS of any OIDC provider. If somehow it did verify, the
// production code in the controller would consider that to be an error and
// would refuse to load that JWTAuthenticator. The production code wants to
// get a signature error, which means that the remote JWKS was successfully
// loaded.
//
// This key was created using:
//
//	key, _ := rsa.GenerateKey(rand.Reader, 2048)
//	t.Log(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
//
//go:embed testdata/test.key
var rsaPrivateKeyToSignMinimalJWTToTriggerJWKSFetch string

func TestMinimalJWTToTriggerJWKSFetch(t *testing.T) {
	hardcodedPEMDecoded, _ := pem.Decode([]byte(rsaPrivateKeyToSignMinimalJWTToTriggerJWKSFetch))
	require.NotNil(t, hardcodedPEMDecoded, "failed to parse hardcoded PEM")
	hardcodedPrivateKey, err := x509.ParsePKCS1PrivateKey(hardcodedPEMDecoded.Bytes)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: hardcodedPrivateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	jwt, err := josejwt.Signed(signer).Claims(josejwt.Claims{}).Serialize()
	require.NoError(t, err)
	require.Equal(t, jwt, minimalJWTToTriggerJWKSFetch)
}

func TestController(t *testing.T) {
	t.Parallel()

	const (
		goodECSigningKeyID  = "some-ec-key-id"
		goodRSASigningKeyID = "some-rsa-key-id"
		goodAudience        = "some-audience"
	)

	hardcodedPEMDecoded, _ := pem.Decode([]byte(rsaPrivateKeyToSignMinimalJWTToTriggerJWKSFetch))
	require.NotNil(t, hardcodedPEMDecoded, "failed to parse hardcoded PEM")
	hardcodedPrivateKey, err := x509.ParsePKCS1PrivateKey(hardcodedPEMDecoded.Bytes)
	require.NoError(t, err)

	goodECSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	goodECSigningAlgo := jose.ES256
	require.NoError(t, err)

	goodRSASigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	goodRSASigningAlgo := jose.RS256

	customGroupsClaim := "my-custom-groups-claim"
	distributedGroups := []string{"some-distributed-group-1", "some-distributed-group-2"}

	goodMux := http.NewServeMux()
	goodOIDCIssuerServer, goodOIDCIssuerServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		goodMux.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	goodOIDCIssuerServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(goodOIDCIssuerServerCAPEM),
	}

	goodMux.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, goodOIDCIssuerServer.URL, goodOIDCIssuerServer.URL+"/jwks.json")
		require.NoError(t, err)
	}))
	goodMux.Handle("/path/to/not/found", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		require.NoError(t, err)
	}))
	goodMux.Handle("/path/to/not/found/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, err := fmt.Fprintf(w, `<html>
		  	<head><title>%s</title></head>
			<body>%s</body>
		</html>`, "404 not found page", "lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz should not reach end of string")
		require.NoError(t, err)
	}))
	goodMux.Handle("/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// Claims without the subject, to be used distributed claims tests.
	// OIDC 1.0 section 5.6.2:
	// A sub (subject) Claim SHOULD NOT be returned from the Claims Provider unless its value
	// is an identifier for the End-User at the Claims Provider (and not for the OpenID Provider or another party);
	// this typically means that a sub Claim SHOULD NOT be provided.
	claimsWithoutSubject := josejwt.Claims{
		Issuer:    goodOIDCIssuerServer.URL,
		Audience:  []string{goodAudience},
		Expiry:    josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
		IssuedAt:  josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}
	goodMux.Handle("/claim_source", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unfortunately we have to set this up pretty early in the test because we can't redeclare
		// mux.Handle. This means that we can't return a different groups claim per test; we have to
		// return both and predecide which groups are returned.
		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: goodECSigningAlgo, Key: goodECSigningKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", goodECSigningKeyID),
		)
		require.NoError(t, err)

		builder := josejwt.Signed(sig).Claims(claimsWithoutSubject)

		builder = builder.Claims(map[string]any{customGroupsClaim: distributedGroups})
		builder = builder.Claims(map[string]any{"groups": distributedGroups})

		distributedClaimsJwt, err := builder.Serialize()
		require.NoError(t, err)

		_, err = w.Write([]byte(distributedClaimsJwt))
		require.NoError(t, err)
	}))
	goodMux.Handle("/wrong_claim_source", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unfortunately we have to set this up pretty early in the test because we can't redeclare
		// mux.Handle. This means that we can't return a different groups claim per test; we have to
		// return both and predecide which groups are returned.
		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: goodECSigningAlgo, Key: goodECSigningKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", goodECSigningKeyID),
		)
		require.NoError(t, err)

		builder := josejwt.Signed(sig).Claims(claimsWithoutSubject)

		builder = builder.Claims(map[string]any{"some-other-claim": distributedGroups})

		distributedClaimsJwt, err := builder.Serialize()
		require.NoError(t, err)

		_, err = w.Write([]byte(distributedClaimsJwt))
		require.NoError(t, err)
	}))

	badMuxInvalidJWKSURI := http.NewServeMux()
	badOIDCIssuerServerInvalidJWKSURIServer, badOIDCIssuerServerInvalidJWKSURIServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		badMuxInvalidJWKSURI.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	badOIDCIssuerServerInvalidJWKSURIServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(badOIDCIssuerServerInvalidJWKSURIServerCAPEM),
	}
	badMuxInvalidJWKSURI.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, badOIDCIssuerServerInvalidJWKSURIServer.URL, "https://.café   .com/café/café/café/coffee/jwks.json")
		require.NoError(t, err)
	}))

	badMuxInvalidJWKSURIScheme := http.NewServeMux()
	badOIDCIssuerServerInvalidJWKSURISchemeServer, badOIDCIssuerServerInvalidJWKSURISchemeServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		badMuxInvalidJWKSURIScheme.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	badOIDCIssuerServerInvalidJWKSURISchemeServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(badOIDCIssuerServerInvalidJWKSURISchemeServerCAPEM),
	}
	badMuxInvalidJWKSURIScheme.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, badOIDCIssuerServerInvalidJWKSURISchemeServer.URL, "http://.café.com/café/café/café/coffee/jwks.json")
		require.NoError(t, err)
	}))

	jwksFetchShouldFailMux := http.NewServeMux()
	jwksFetchShouldFailServer, jwksFetchShouldFailServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		jwksFetchShouldFailMux.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	jwksFetchShouldFailServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(jwksFetchShouldFailServerCAPEM),
	}
	jwksFetchShouldFailMux.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, jwksFetchShouldFailServer.URL, jwksFetchShouldFailServer.URL+"/fetch/will/fail/jwks.json")
		require.NoError(t, err)
	}))

	// No real OIDC provider should ever be using our hardcoded private key as a signing key, so this should never happen
	// in real life. Simulating this here just so we can have test coverage for the expected error that the production
	// code should return in this case.
	badMuxUsesOurHardcodedPrivateKey := http.NewServeMux()
	badOIDCIssuerUsesOurHardcodedPrivateKeyServer, badOIDCIssuerUsesOurHardcodedPrivateKeyServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		badMuxUsesOurHardcodedPrivateKey.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	badOIDCIssuerUsesOurHardcodedPrivateKeyServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(badOIDCIssuerUsesOurHardcodedPrivateKeyServerCAPEM),
	}
	badMuxUsesOurHardcodedPrivateKey.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, badOIDCIssuerUsesOurHardcodedPrivateKeyServer.URL, badOIDCIssuerUsesOurHardcodedPrivateKeyServer.URL+"/jwks.json")
		require.NoError(t, err)
	}))
	badMuxUsesOurHardcodedPrivateKey.Handle("/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ecJWK := jose.JSONWebKey{
			Key:       hardcodedPrivateKey,
			KeyID:     goodRSASigningKeyID,
			Algorithm: string(goodRSASigningAlgo),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{ecJWK.Public()},
		}
		require.NoError(t, json.NewEncoder(w).Encode(jwks))
	}))

	goodIssuer := goodOIDCIssuerServer.URL
	someOtherIssuer := "https://some-other-issuer.com" // placeholder only for tests that don't get far enough to make requests

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenMetav1Now := metav1.NewTime(nowDoesntMatter)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	timeInThePast := time.Date(1111, time.January, 1, 1, 1, 1, 111111, time.Local)
	frozenTimeInThePast := metav1.NewTime(timeInThePast)

	someJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      goodOIDCIssuerServerTLSSpec,
	}
	someJWTAuthenticatorSpecWithCAInSecret := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS: &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
				Kind: "Secret",
				Name: "secret-with-ca",
				Key:  "ca.crt",
			},
		},
	}
	someSecretWithCA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-with-ca",
			Namespace: "concierge",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": goodOIDCIssuerServerCAPEM,
		},
	}
	someJWTAuthenticatorSpecWithCAInConfigMap := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS: &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
				Kind: "ConfigMap",
				Name: "configmap-with-ca",
				Key:  "ca.crt",
			},
		},
	}
	someConfigMapWithCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "configmap-with-ca",
			Namespace: "concierge",
		},
		Data: map[string]string{
			"ca.crt": string(goodOIDCIssuerServerCAPEM),
		},
	}
	someJWTAuthenticatorSpecWithUsernameClaim := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      goodOIDCIssuerServerTLSSpec,
		Claims: authenticationv1alpha1.JWTTokenClaims{
			Username: "my-custom-username-claim",
		},
	}
	someJWTAuthenticatorSpecWithGroupsClaim := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      goodOIDCIssuerServerTLSSpec,
		Claims: authenticationv1alpha1.JWTTokenClaims{
			Groups: customGroupsClaim,
		},
	}
	otherJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   someOtherIssuer,
		Audience: goodAudience,
		// Some random generated cert
		// Issuer: C=US, O=Pivotal
		// No SAN provided
		TLS: &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"},
	}
	missingTLSJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
	}
	invalidTLSJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   someOtherIssuer,
		Audience: goodAudience,
		TLS:      &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: "invalid base64-encoded data"},
	}
	invalidIssuerJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   "https://.café   .com/café/café/café/coffee",
		Audience: goodAudience,
		TLS:      goodOIDCIssuerServerTLSSpec,
	}
	invalidIssuerSchemeJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   "http://.café.com/café/café/café/coffee",
		Audience: goodAudience,
		TLS:      goodOIDCIssuerServerTLSSpec,
	}
	validIssuerURLButDoesNotExistJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer + "/foo/bar/baz/shizzle",
		Audience: goodAudience,
	}
	badIssuerJWKSURIJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   badOIDCIssuerServerInvalidJWKSURIServer.URL,
		Audience: goodAudience,
		TLS:      badOIDCIssuerServerInvalidJWKSURIServerTLSSpec,
	}
	badIssuerJWKSURISchemeJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   badOIDCIssuerServerInvalidJWKSURISchemeServer.URL,
		Audience: goodAudience,
		TLS:      badOIDCIssuerServerInvalidJWKSURISchemeServerTLSSpec,
	}
	badIssuerUsesOurHardcodedPrivateKeyJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   badOIDCIssuerUsesOurHardcodedPrivateKeyServer.URL,
		Audience: goodAudience,
		TLS:      badOIDCIssuerUsesOurHardcodedPrivateKeyServerTLSSpec,
	}
	jwksFetchShouldFailJWTAuthenticatorSpec := &authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   jwksFetchShouldFailServer.URL,
		Audience: goodAudience,
		TLS:      jwksFetchShouldFailServerTLSSpec,
	}

	happyReadyCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "Ready",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the JWTAuthenticator is ready",
		}
	}
	sadReadyCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "Ready",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "NotReady",
			Message:            "the JWTAuthenticator is not ready: see other conditions for details",
		}
	}

	happyTLSConfigurationValidCAParsed := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.tls is valid: loaded TLS configuration",
		}
	}
	happyTLSConfigurationValidNoCA := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.tls is valid: no TLS configuration provided",
		}
	}
	sadTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidTLSConfig",
			Message:            "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7",
		}
	}

	happyIssuerURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "issuer is a valid URL",
		}
	}
	sadIssuerURLValidInvalid := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURL",
			Message:            fmt.Sprintf(`spec.issuer URL is invalid: parse "%s": invalid character " " in host name`, issuer),
		}
	}

	sadIssuerURLValidInvalidScheme := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURLScheme",
			Message:            fmt.Sprintf("spec.issuer %s has invalid scheme, require 'https'", issuer),
		}
	}

	sadIssuerURLValidInvalidFragment := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURLContainsFragment",
			Message:            fmt.Sprintf("spec.issuer %s cannot include fragment", issuer),
		}
	}

	sadIssuerURLValidInvalidQueryParams := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURLContainsQueryParams",
			Message:            fmt.Sprintf("spec.issuer %s cannot include query params", issuer),
		}
	}

	sadIssuerURLValidInvalidWellKnownEndpoint := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURLContainsWellKnownEndpoint",
			Message:            fmt.Sprintf("spec.issuer %s cannot include path '/.well-known/openid-configuration'", issuer),
		}
	}

	happyAuthenticatorValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AuthenticatorValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "authenticator initialized",
		}
	}
	unknownAuthenticatorValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AuthenticatorValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	// NOTE: we can't reach this error the way our code is written.
	// We check many things and fail early, resulting in an "Unknown" Authenticator status.
	// The only possible fail for the Authenticator itself would require us to allow more
	// configuration for users.  See comments in the jwtauthenticator.go newCachedJWTAuthenticator()
	// func itself for more information.
	// sadAuthenticatorValid := func() metav1.Condition {}

	happyDiscoveryURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "discovery performed successfully",
		}
	}
	unknownDiscoveryURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	sadDiscoveryURLValidx509 := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidDiscoveryProbe",
			Message:            fmt.Sprintf(`could not perform oidc discovery on provider issuer: Get "%s/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`, issuer),
		}
	}
	sadDiscoveryURLValidConnectionRefused := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidDiscoveryProbe",
			Message:            fmt.Sprintf(`could not perform oidc discovery on provider issuer: Get "%s/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`, issuer),
		}
	}

	sadDiscoveryURLValidExcessiveLongError := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidDiscoveryProbe",
			Message:            "could not perform oidc discovery on provider issuer: 404 Not Found: <html>\n\t\t  \t<head><title>404 not found page</title></head>\n\t\t\t<body>lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 charact [truncated 534 chars]",
		}
	}

	happyJWKSURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "jwks_uri is a valid URL",
		}
	}
	unknownJWKSURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSURLValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	sadJWKSURLValidParseURI := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidProviderJWKSURL",
			Message:            `could not parse provider jwks_uri: parse "` + issuer + `": invalid character " " in host name`,
		}
	}
	sadJWKSURLValidScheme := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidProviderJWKSURLScheme",
			Message:            `jwks_uri ` + issuer + ` has invalid scheme, require 'https'`,
		}
	}
	happyJWKSFetch := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSFetchValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "successfully fetched jwks",
		}
	}
	unknownJWKSFetch := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSFetchValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	sadJWKSFetch := func(msg string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "JWKSFetchValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidCouldNotFetchJWKS",
			Message:            msg,
		}
	}

	allHappyConditionsSuccess := func(issuer string, someTime metav1.Time, observedGeneration int64) []metav1.Condition {
		return conditionstestutil.SortByType([]metav1.Condition{
			happyAuthenticatorValid(someTime, observedGeneration),
			happyDiscoveryURLValid(someTime, observedGeneration),
			happyIssuerURLValid(someTime, observedGeneration),
			happyJWKSURLValid(someTime, observedGeneration),
			happyJWKSFetch(someTime, observedGeneration),
			happyReadyCondition(someTime, observedGeneration),
			happyTLSConfigurationValidCAParsed(someTime, observedGeneration),
		})
	}
	jwtAuthenticatorsGVR := schema.GroupVersionResource{
		Group:    "authentication.concierge.pinniped.dev",
		Version:  "v1alpha1",
		Resource: "jwtauthenticators",
	}
	jwtAUthenticatorGVK := schema.GroupVersionKind{
		Group:   "authentication.concierge.pinniped.dev",
		Version: "v1alpha1",
		Kind:    "JWTAuthenticator",
	}
	tests := []struct {
		name                 string
		cache                func(*testing.T, *authncache.Cache, bool)
		jwtAuthenticators    []runtime.Object
		secretsAndConfigMaps []runtime.Object
		// for modifying the clients to hack in arbitrary api responses
		configClient func(*conciergefake.Clientset)
		wantClose    bool
		// Only errors that are non-config related errors are returned from the sync loop.
		// Errors such as url.Parse of the issuer are not returned as they imply a user error.
		// Since these errors trigger a resync, we are careful only to return an error when
		// something can be automatically corrected on a retry (ie an error that might be networking).
		wantSyncErr                         testutil.RequireErrorStringFunc
		wantLogs                            []map[string]any
		wantActions                         func() []coretesting.Action
		wantUsernameClaim                   string
		wantGroupsClaim                     string
		wantNamesOfJWTAuthenticatorsInCache []string
		skipTestingCachedAuthenticator      bool
	}{
		{
			name: "Sync: no JWTAuthenticators found results in no errors and no status conditions",
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "jwtcachefiller-controller",
					"message":   "No JWTAuthenticators found",
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
				}
			},
		},
		{
			name: "Sync: valid and unchanged JWTAuthenticator: loop will preserve existing status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: multiple valid and multiple invalid JWTAuthenticators",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "existing-jwt-authenticator",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-jwt-authenticator",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "invalid-jwt-authenticator",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
				},
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "another-invalid-jwt-authenticator",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
				},
			},
			wantSyncErr: testutil.WantExactErrorString("[" +
				`error for JWTAuthenticator another-invalid-jwt-authenticator: could not parse provider jwks_uri: parse "https://.café   .com/café/café/café/coffee/jwks.json": invalid character " " in host name` +
				", " +
				`error for JWTAuthenticator invalid-jwt-authenticator: could not parse provider jwks_uri: parse "https://.café   .com/café/café/café/coffee/jwks.json": invalid character " " in host name` +
				"]",
			),
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "jwtcachefiller-controller",
					"message":   "added new jwt authenticator",
					"issuer":    goodIssuer,
					"jwtAuthenticator": map[string]any{
						"name": "existing-jwt-authenticator",
					},
				},
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "jwtcachefiller-controller",
					"message":   "added new jwt authenticator",
					"issuer":    goodIssuer,
					"jwtAuthenticator": map[string]any{
						"name": "new-jwt-authenticator",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateValidStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-jwt-authenticator",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateValidStatusAction.Subresource = "status"
				updateInvalidStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "invalid-jwt-authenticator",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadJWKSURLValidParseURI("https://.café   .com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateInvalidStatusAction.Subresource = "status"
				updateValidStatusAction.Subresource = "status"
				updateAnotherInvalidStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "another-invalid-jwt-authenticator",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadJWKSURLValidParseURI("https://.café   .com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateAnotherInvalidStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateAnotherInvalidStatusAction,
					updateInvalidStatusAction,
					updateValidStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{
				"existing-jwt-authenticator",
				"new-jwt-authenticator",
			},
		},
		{
			name: "Sync: changed JWTAuthenticator: loop will update timestamps only on relevant statuses",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 1233),
							[]metav1.Condition{
								// sad and unknown will update with new statuses and timestamps
								sadReadyCondition(frozenTimeInThePast, 1232),
								sadDiscoveryURLValidx509(goodIssuer, frozenTimeInThePast, 1231),
								unknownAuthenticatorValid(frozenTimeInThePast, 1232),
								unknownJWKSURLValid(frozenTimeInThePast, 1111),
								unknownJWKSFetch(frozenTimeInThePast, 1122),
								// this one will remain unchanged as it was good to begin with
								happyTLSConfigurationValidCAParsed(frozenTimeInThePast, 4321),
							},
						),
						Phase: "Error",
					},
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 1234),
							[]metav1.Condition{
								// this timestamp should not have updated, it didn't change.
								happyTLSConfigurationValidCAParsed(frozenTimeInThePast, 1234),
							},
						),
						Phase: "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid JWTAuthenticator with CA: loop will complete successfully and update status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid JWTAuthenticator with CA from Secret: loop will complete successfully and update status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInSecret,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someSecretWithCA,
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInSecret,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid JWTAuthenticator with CA from ConfigMap: loop will complete successfully and update status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInConfigMap,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someConfigMapWithCA,
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInConfigMap,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: JWTAuthenticator with custom username claim: loop will complete successfully and update status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithUsernameClaim,
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithUsernameClaim,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantUsernameClaim:                   someJWTAuthenticatorSpecWithUsernameClaim.Claims.Username,
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: JWTAuthenticator with custom groups claim: loop will complete successfully and update status conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithGroupsClaim,
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithGroupsClaim,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantGroupsClaim:                     someJWTAuthenticatorSpecWithGroupsClaim.Claims.Groups,
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: JWTAuthenticator with new spec fields: loop will close previous instance of JWTAuthenticator and complete successfully and update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				oldCA, err := base64.StdEncoding.DecodeString(otherJWTAuthenticatorSpec.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *otherJWTAuthenticatorSpec, string(oldCA), wantClose),
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
			wantClose:                           true,
		},
		{
			name: "Sync: previously cached JWTAuthenticator gets new spec fields, but status update fails: loop will leave it in the cache and avoid calling close",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				oldCA, err := base64.StdEncoding.DecodeString(otherJWTAuthenticatorSpec.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *otherJWTAuthenticatorSpec, string(oldCA), wantClose),
				)
			},
			configClient: func(client *conciergefake.Clientset) {
				client.PrependReactor(
					"update",
					"jwtauthenticators",
					func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("some update error")
					},
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []map[string]any{},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			skipTestingCachedAuthenticator:      true,
			wantSyncErr:                         testutil.WantExactErrorString("error for JWTAuthenticator test-name: some update error"),
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"}, // keeps the old entry in the cache
			wantClose:                           false,
		},
		{
			name: "Sync: JWTAuthenticator with external and changed CA bundle: loop will close previous instance of JWTAuthenticator and complete successfully and update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *someJWTAuthenticatorSpecWithCAInSecret, "some-stale-ca-bundle-pem-content-from-secret", wantClose),
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInSecret,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someSecretWithCA,
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpecWithCAInSecret,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantClose:                           true,
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: JWTAuthenticator with no change: loop will abort early and not update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				oldCA, err := base64.StdEncoding.DecodeString(someJWTAuthenticatorSpec.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *someJWTAuthenticatorSpec, string(oldCA), wantClose),
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "actual jwt authenticator and desired jwt authenticator are the same",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
				}
			},
			wantClose:                           false,
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
			// skip the tests because the authenticator pre-loaded into the cache is the mock version that was added above
			skipTestingCachedAuthenticator: true,
		},
		{
			name: "Sync: authenticator update when cached authenticator is the wrong data type, which should never really happen: loop will complete successfully and update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				ctrl := gomock.NewController(t)
				t.Cleanup(func() {
					ctrl.Finish()
				})
				mockCacheValue := mockcachevalue.NewMockValue(ctrl)
				mockCacheValue.EXPECT().Close().Times(1)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					// Only entries of type cachedJWTAuthenticator are ever put into the cache, so this should never really happen.
					// This test is to provide coverage on the production code which reads from the cache and casts those entries to
					// the appropriate data type.
					mockCacheValue,
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":      "info",
					"timestamp":  "2099-08-08T13:57:36.123456Z",
					"logger":     "jwtcachefiller-controller",
					"message":    "wrong JWT authenticator type in cache",
					"actualType": "*mockcachevalue.MockValue",
				},
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "jwtcachefiller-controller",
					"message":   "added new jwt authenticator",
					"issuer":    goodIssuer,
					"jwtAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid JWTAuthenticator without CA: loop will fail to cache the authenticator, will write failed and unknown status conditions, and will enqueue resync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *missingTLSJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *missingTLSJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadDiscoveryURLValidx509(goodIssuer, frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			// no explicit logs, this is an issue of config, the user must provide TLS config for the
			// custom cert provided for this server.
			wantSyncErr: testutil.WantSprintfErrorString(`error for JWTAuthenticator test-name: could not perform oidc discovery on provider issuer: Get "%s/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`, goodIssuer),
		},
		{
			name: "validateTLS: JWTAuthenticator with invalid CA: loop will fail, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(someOtherIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "previously valid cached authenticator (which did not specify a CA bundle) changes and becomes invalid due to any problem with the CA bundle: loop will fail sync, will write failed and unknown status conditions, and will remove authenticator from cache and close it",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					// Force an invalid spec into the cache, which is not very realistic, but it simulates a case
					// where the CA bundle goes from being cached as empty to being an error during validation,
					// without causing any changes in the spec. This test wants to prove that the rest of the
					// validations get run and the resource is update, just in case that can happen somehow.
					newCacheValue(t, *invalidTLSJWTAuthenticatorSpec, "", wantClose),
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(someOtherIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantClose: true,
		},
		{
			name: "previously valid cached authenticator's spec changes and becomes invalid for any other reason (this test uses an invalid spec.issuer URL): loop will fail sync, will write failed and unknown status conditions, and will remove authenticator from cache",
			cache: func(t *testing.T, cache *authncache.Cache, wantClose bool) {
				oldCA, err := base64.StdEncoding.DecodeString(someJWTAuthenticatorSpec.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "JWTAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, *someJWTAuthenticatorSpec, string(oldCA), wantClose),
				)
			},
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{}, // it was removed from the cache
			wantClose:                           true,       // the removed cache entry was also closed
		},
		{
			name: "validateIssuer: parsing error (spec.issuer URL is invalid): loop will fail sync, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "validateIssuer: parsing error (spec.issuer URL has invalid scheme, requires https): loop will fail sync, will write failed and unknown conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerSchemeJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerSchemeJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalidScheme("http://.café.com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "validateIssuer: issuer cannot include fragment: loop will fail sync, will write failed and unknown conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/#do-not-include-fragment",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/#do-not-include-fragment",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalidFragment("https://www.example.com/foo/bar/#do-not-include-fragment", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "validateIssuer: issuer cannot include query params: loop will fail sync, will write failed and unknown conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/?query-params=not-allowed",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/?query-params=not-allowed",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalidQueryParams("https://www.example.com/foo/bar/?query-params=not-allowed", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "validateIssuer: issuer cannot include .well-known in path: loop will fail sync, will write failed and unknown conditions, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/.well-known/openid-configuration",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://www.example.com/foo/bar/.well-known/openid-configuration",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
								sadIssuerURLValidInvalidWellKnownEndpoint("https://www.example.com/foo/bar/.well-known/openid-configuration", frozenMetav1Now, 0),
								unknownDiscoveryURLValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
		},
		{
			name: "validateProviderDiscovery: could not perform oidc discovery on provider issuer: loop will fail sync, will write failed and unknown conditions, and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *validIssuerURLButDoesNotExistJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *validIssuerURLButDoesNotExistJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								sadDiscoveryURLValidConnectionRefused(goodIssuer+"/foo/bar/baz/shizzle", frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncErr: testutil.WantExactErrorString(`error for JWTAuthenticator test-name: could not perform oidc discovery on provider issuer: Get "` + goodIssuer + `/foo/bar/baz/shizzle/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`),
		},
		{
			name: "validateProviderDiscovery: excessively long errors truncated: loop will fail sync, will write failed and unknown conditions, and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   goodIssuer + "/path/to/not/found",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   goodIssuer + "/path/to/not/found",
						Audience: goodAudience,
						TLS:      goodOIDCIssuerServerTLSSpec,
					},
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								sadDiscoveryURLValidExcessiveLongError(goodIssuer+"/path/to/not/found", frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								unknownJWKSURLValid(frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
								happyTLSConfigurationValidCAParsed(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			// not currently truncating the logged err
			wantSyncErr: testutil.WantExactErrorString("error for JWTAuthenticator test-name: could not perform oidc discovery on provider issuer: 404 Not Found: <html>\n\t\t  \t<head><title>404 not found page</title></head>\n\t\t\t<body>lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz lots of text that is at least 300 characters long 0123456789 abcdefghijklmnopqrstuvwxyz should not reach end of string</body>\n\t\t</html>"),
		},
		// cannot be tested currently the way the coreos lib works.
		// the constructor requires an issuer in the payload and validates the issuer matches the actual issuer,
		// which ensures the .Claims() parsing cannot fail (in the current impl)
		// { name: "validateProviderJWKSURL: could not get provider jwks_uri... ",},
		{
			name: "validateProviderJWKSURL: could not parse provider jwks_uri: loop will fail sync, will write failed and unknown conditions, and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadJWKSURLValidParseURI("https://.café   .com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncErr: testutil.WantExactErrorString(`error for JWTAuthenticator test-name: could not parse provider jwks_uri: parse "https://.café   .com/café/café/café/coffee/jwks.json": invalid character " " in host name`),
		},
		{
			name: "validateProviderJWKSURL: invalid scheme, requires 'https': loop will fail sync, will write failed and unknown conditions, and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURISchemeJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURISchemeJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadJWKSURLValidScheme("http://.café.com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
								unknownJWKSFetch(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncErr: testutil.WantExactErrorString("error for JWTAuthenticator test-name: jwks_uri http://.café.com/café/café/café/coffee/jwks.json has invalid scheme, require 'https'"),
		},
		{
			name: "validateProviderJWKSURL: remote jwks should not have been able to verify hardcoded test jwt token: loop will fail sync, will write failed and unknown conditions, and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerUsesOurHardcodedPrivateKeyJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerUsesOurHardcodedPrivateKeyJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								happyDiscoveryURLValid(frozenMetav1Now, 0),
								sadJWKSFetch("remote jwks should not have been able to verify hardcoded test jwt token",
									frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncErr: testutil.WantExactErrorString("error for JWTAuthenticator test-name: remote jwks should not have been able to verify hardcoded test jwt token"),
		},
		{
			name: "validateJWKSFetch: could not fetch keys: loop will fail sync, will write failed and unknown status conditions, and will enqueue a resync",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *jwksFetchShouldFailJWTAuthenticatorSpec,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *jwksFetchShouldFailJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyIssuerURLValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadJWKSFetch("could not fetch keys: fetching keys oidc: get keys failed: 404 Not Found 404 page not found\n",
									frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncErr: testutil.WantExactErrorString("error for JWTAuthenticator test-name: could not fetch keys: fetching keys oidc: get keys failed: 404 Not Found 404 page not found\n"),
		},
		{
			name: "updateStatus: called with matching original and updated conditions: will not make request to update conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "updateStatus: called with different original and updated conditions: will make request to update conditions",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "SomethingBeforeUpdating",
					},
				},
			},
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]any{
					"name": "test-name",
				},
			}},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantNamesOfJWTAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "updateStatus: given a valid JWTAuthenticator spec, when update request fails: error will enqueue a resync and the authenticator will not be added to the cache",
			jwtAuthenticators: []runtime.Object{
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
				},
			},
			configClient: func(client *conciergefake.Clientset) {
				client.PrependReactor(
					"update",
					"jwtauthenticators",
					func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("some update error")
					},
				)
			},
			wantActions: func() []coretesting.Action {
				// This captures that there was an attempt to update to Ready, allHappyConditions,
				// but the wantSyncErr indicates that there is a failure, so the JWTAuthenticator
				// remains with a bad phase and at least 1 sad condition
				updateStatusAction := coretesting.NewUpdateAction(jwtAuthenticatorsGVR, "", &authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *someJWTAuthenticatorSpec,
					Status: authenticationv1alpha1.JWTAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(jwtAuthenticatorsGVR, jwtAUthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(jwtAuthenticatorsGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantLogs:                            []map[string]any{},
			wantSyncErr:                         testutil.WantExactErrorString("error for JWTAuthenticator test-name: some update error"),
			wantNamesOfJWTAuthenticatorsInCache: []string{}, // even though the authenticator was valid, do not cache it because the status update failed
		},
		// cannot be tested the way we are invoking oidc.New as we don't provide enough configuration
		// knobs to actually invoke the code in a broken way.  We always give a good client, good keys, and
		// good signing algos.  In the future if we allow any of these to be configured we may have opportunity
		// to test for errors.
		// {name: "newCachedJWTAuthenticator: could not initialize oidc authenticator..." },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := conciergefake.NewSimpleClientset(tt.jwtAuthenticators...)
			if tt.configClient != nil {
				tt.configClient(pinnipedAPIClient)
			}
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			kubeInformers := kubeinformers.NewSharedInformerFactory(kubernetesfake.NewSimpleClientset(tt.secretsAndConfigMaps...), 0)
			cache := authncache.New()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			if tt.cache != nil {
				tt.cache(t, cache, tt.wantClose)
			}

			controller := New(
				"concierge", // namespace for the controller
				cache,
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().JWTAuthenticators(),
				kubeInformers.Core().V1().Secrets(),
				kubeInformers.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
				frozenClock,
				logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantSyncErr != nil {
				testutil.RequireErrorStringFromErr(t, err, tt.wantSyncErr)
			} else {
				require.NoError(t, err)
			}

			if !assert.ElementsMatch(t, tt.wantActions(), pinnipedAPIClient.Actions()) {
				// cmp.Diff is superior to require.ElementsMatch in terms of readability here.
				// require.ElementsMatch will handle pointers better than require.Equal, but
				// the timestamps are still incredibly verbose.
				require.Fail(t, cmp.Diff(tt.wantActions(), pinnipedAPIClient.Actions()), "actions should be exactly the expected number of actions and also contain the correct resources")
			}

			require.Equal(t, len(tt.wantNamesOfJWTAuthenticatorsInCache), len(cache.Keys()), fmt.Sprintf("expected cache entries is incorrect. wanted:%d, got: %d, keys: %v", len(tt.wantNamesOfJWTAuthenticatorsInCache), len(cache.Keys()), cache.Keys()))

			actualLogLines := testutil.SplitByNewline(log.String())
			require.Equal(t, len(tt.wantLogs), len(actualLogLines), "log line count should be correct")

			for logLineNum, logLine := range actualLogLines {
				require.NotNil(t, tt.wantLogs[logLineNum], "expected log line should never be empty")
				var lineStruct map[string]any
				err := json.Unmarshal([]byte(logLine), &lineStruct)
				require.NoError(t, err)

				require.Equal(t, tt.wantLogs[logLineNum]["level"], lineStruct["level"], fmt.Sprintf("log line (%d) log level should be correct (in: %s)", logLineNum, lineStruct))

				require.Equal(t, tt.wantLogs[logLineNum]["timestamp"], lineStruct["timestamp"], fmt.Sprintf("log line (%d) timestamp should be correct (in: %s)", logLineNum, lineStruct))
				require.Equal(t, tt.wantLogs[logLineNum]["logger"], lineStruct["logger"], fmt.Sprintf("log line (%d) logger should be correct", logLineNum))
				require.NotEmpty(t, lineStruct["caller"], fmt.Sprintf("log line (%d) caller should not be empty", logLineNum))
				require.Equal(t, tt.wantLogs[logLineNum]["message"], lineStruct["message"], fmt.Sprintf("log line (%d) message should be correct", logLineNum))
				if lineStruct["issuer"] != nil {
					require.Equal(t, tt.wantLogs[logLineNum]["issuer"], lineStruct["issuer"], fmt.Sprintf("log line (%d) issuer should be correct", logLineNum))
				}
				if lineStruct["jwtAuthenticator"] != nil {
					require.Equal(t, tt.wantLogs[logLineNum]["jwtAuthenticator"], lineStruct["jwtAuthenticator"], fmt.Sprintf("log line (%d) jwtAuthenticator should be correct", logLineNum))
				}
				if lineStruct["actualType"] != nil {
					require.Equal(t, tt.wantLogs[logLineNum]["actualType"], lineStruct["actualType"], fmt.Sprintf("log line (%d) actualType should be correct", logLineNum))
				}
			}

			for _, name := range tt.wantNamesOfJWTAuthenticatorsInCache {
				// We expected the cache to have an entry, so pull that entry from the cache and test it.
				expectedCacheKey := authncache.Key{
					APIGroup: authenticationv1alpha1.GroupName,
					Kind:     "JWTAuthenticator",
					Name:     name,
				}
				temp := cache.Get(expectedCacheKey)
				require.NotNil(t, temp)
				require.IsType(t, &cachedJWTAuthenticator{}, temp)

				if tt.skipTestingCachedAuthenticator {
					continue // skip the rest of this test for this authenticator
				}

				require.NotNil(t, temp.(*cachedJWTAuthenticator).Token)
				cachedAuthenticator, ok := temp.(tokenAuthenticatorCloser)
				require.True(t, ok)

				// Schedule it to be closed at the end of the test.
				t.Cleanup(cachedAuthenticator.Close)

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
					goodIssuer,
				) {
					t.Run(test.name, func(t *testing.T) {
						t.Parallel()

						wellKnownClaims := josejwt.Claims{
							Issuer:    goodIssuer,
							Subject:   goodSubject,
							Audience:  []string{goodAudience},
							Expiry:    josejwt.NewNumericDate(time.Now().Add(time.Hour)),
							NotBefore: josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
							IssuedAt:  josejwt.NewNumericDate(time.Now().Add(-time.Hour)),
						}
						var groups any
						username := goodUsername
						if test.jwtClaims != nil {
							test.jwtClaims(&wellKnownClaims, &groups, &username)
						}

						var signingKey any = goodECSigningKey
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
							test.distributedGroupsClaimURL,
							tt.wantUsernameClaim,
							username,
						)

						// Loop for a while here to allow the underlying OIDC authenticator to initialize itself asynchronously.
						var (
							rsp           *authenticator.Response
							authenticated bool
							err           error
						)
						_ = wait.PollUntilContextTimeout(context.Background(), 10*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
							require.NotEmpty(t, cachedAuthenticator)
							rsp, authenticated, err = cachedAuthenticator.AuthenticateToken(context.Background(), jwt)
							return !isNotInitialized(err), nil
						})
						if test.wantErr != nil {
							testutil.RequireErrorStringFromErr(t, err, test.wantErr)
						} else {
							require.NoError(t, err)
							require.Equal(t, test.wantResponse, rsp)
							require.Equal(t, test.wantAuthenticated, authenticated)
						}
					})
				}
			}
		})
	}
}

// isNotInitialized checks if the error is the internally-defined "oidc: authenticator not initialized" error from
// the underlying OIDC authenticator or "verifier is not initialized" from verifying distributed claims,
// both of which are initialized asynchronously.
func isNotInitialized(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "authenticator not initialized") || strings.Contains(err.Error(), "verifier not initialized"))
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
	issuer string,
) []struct {
	name                      string
	jwtClaims                 func(wellKnownClaims *josejwt.Claims, groups *any, username *string)
	jwtSignature              func(key *any, algo *jose.SignatureAlgorithm, kid *string)
	wantResponse              *authenticator.Response
	wantAuthenticated         bool
	wantErr                   testutil.RequireErrorStringFunc
	distributedGroupsClaimURL string
} {
	tests := []struct {
		name                      string
		jwtClaims                 func(wellKnownClaims *josejwt.Claims, groups *any, username *string)
		jwtSignature              func(key *any, algo *jose.SignatureAlgorithm, kid *string)
		wantResponse              *authenticator.Response
		wantAuthenticated         bool
		wantErr                   testutil.RequireErrorStringFunc
		distributedGroupsClaimURL string
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
			jwtSignature: func(key *any, algo *jose.SignatureAlgorithm, kid *string) {
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
			jwtClaims: func(_ *josejwt.Claims, groups *any, username *string) {
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
			name: "good token with good distributed groups",
			jwtClaims: func(claims *josejwt.Claims, groups *any, username *string) {
			},
			distributedGroupsClaimURL: issuer + "/claim_source",
			wantResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   goodUsername,
					Groups: []string{"some-distributed-group-1", "some-distributed-group-2"},
				},
			},
			wantAuthenticated: true,
		},
		{
			name: "distributed groups returns a 404",
			jwtClaims: func(claims *josejwt.Claims, groups *any, username *string) {
			},
			distributedGroupsClaimURL: issuer + "/not_found_claim_source",
			wantErr:                   testutil.WantMatchingErrorString(`oidc: could not expand distributed claims: while getting distributed claim "` + expectedGroupsClaim + `": error while getting distributed claim JWT: 404 Not Found`),
		},
		{
			name: "distributed groups doesn't return the right claim",
			jwtClaims: func(claims *josejwt.Claims, groups *any, username *string) {
			},
			distributedGroupsClaimURL: issuer + "/wrong_claim_source",
			wantErr:                   testutil.WantMatchingErrorString(`oidc: could not expand distributed claims: jwt returned by distributed claim endpoint "` + issuer + `/wrong_claim_source" did not contain claim: `),
		},
		{
			name: "good token with groups as string",
			jwtClaims: func(_ *josejwt.Claims, groups *any, username *string) {
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
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
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
			jwtClaims: func(_ *josejwt.Claims, groups *any, username *string) {
				*groups = map[string]string{"not an array": "or a string"}
			},
			wantErr: testutil.WantMatchingErrorString("oidc: parse groups claim \"" + expectedGroupsClaim + "\": json: cannot unmarshal object into Go value of type string"),
		},
		{
			name: "bad token with wrong issuer",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.Issuer = "wrong-issuer"
			},
			wantResponse:      nil,
			wantAuthenticated: false,
		},
		{
			name: "bad token with no audience",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.Audience = nil
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: expected audience "some-audience" got \[\]`),
		},
		{
			name: "bad token with wrong audience",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.Audience = []string{"wrong-audience"}
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: expected audience "some-audience" got \["wrong-audience"\]`),
		},
		{
			name: "bad token with nbf in the future",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.NotBefore = josejwt.NewNumericDate(time.Date(3020, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: current time .* before the nbf \(not before\) time: 3020-.*`),
		},
		{
			name: "bad token with exp in past",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.Expiry = josejwt.NewNumericDate(time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: token is expired \(Token Expiry: .+`),
		},
		{
			name: "bad token without exp",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				claims.Expiry = nil
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: token is expired \(Token Expiry: .+`),
		},
		{
			name: "token does not have username claim",
			jwtClaims: func(claims *josejwt.Claims, _ *any, username *string) {
				*username = ""
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: parse username claims "` + expectedUsernameClaim + `": claim not present`),
		},
		{
			name: "signing key is wrong",
			jwtSignature: func(key *any, algo *jose.SignatureAlgorithm, kid *string) {
				var err error
				*key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				*algo = jose.ES256
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: failed to verify signature: failed to verify id token signature`),
		},
		{
			name: "signing algo is unsupported",
			jwtSignature: func(key *any, algo *jose.SignatureAlgorithm, kid *string) {
				var err error
				*key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				*algo = jose.ES384
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: id token signed with unsupported algorithm, expected \["RS256" "ES256"\] got "ES384"`),
		},
	}

	return tests
}

func createJWT(
	t *testing.T,
	signingKey any,
	signingAlgo jose.SignatureAlgorithm,
	kid string,
	claims *josejwt.Claims,
	groupsClaim string,
	groupsValue any,
	distributedGroupsClaimURL string,
	usernameClaim string,
	usernameValue string,
) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: signingAlgo, Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	builder := josejwt.Signed(sig).Claims(claims)
	if groupsValue != nil {
		builder = builder.Claims(map[string]any{groupsClaim: groupsValue})
	}
	if distributedGroupsClaimURL != "" {
		builder = builder.Claims(map[string]any{"_claim_names": map[string]string{groupsClaim: "src1"}})
		builder = builder.Claims(map[string]any{"_claim_sources": map[string]any{"src1": map[string]string{"endpoint": distributedGroupsClaimURL}}})
	}
	if usernameValue != "" {
		builder = builder.Claims(map[string]any{usernameClaim: usernameValue})
	}
	jwt, err := builder.Serialize()
	require.NoError(t, err)

	return jwt
}

func newCacheValue(t *testing.T, spec authenticationv1alpha1.JWTAuthenticatorSpec, caBundle string, wantClose bool) authncache.Value {
	t.Helper()
	wasClosed := false

	t.Cleanup(func() {
		require.Equal(t, wantClose, wasClosed)
	})

	return &cachedJWTAuthenticator{
		spec:         &spec,
		caBundleHash: tlsconfigutil.NewCABundleHash([]byte(caBundle)),
		cancel: func() {
			wasClosed = true
		},
	}
}

func TestControllerFilterSecret(t *testing.T) {
	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "should return true for a secret of the type Opaque",
			secret: &corev1.Secret{
				Type: corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type TLS",
			secret: &corev1.Secret{
				Type: corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return false for a secret of the wrong type",
			secret: &corev1.Secret{
				Type: "other-type",
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
		},
		{
			name: "should return false for a resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
			frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			pinnipedAPIClient := conciergefake.NewSimpleClientset()
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				"concierge", // namespace for the controller
				authncache.New(),
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().JWTAuthenticators(),
				secretInformer,
				configMapInformer,
				observableInformers.WithInformer,
				frozenClock,
				logger)

			unrelated := &corev1.Secret{}
			filter := observableInformers.GetFilterForInformer(secretInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.secret, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.secret))
		})
	}
}

func TestControllerFilterConfigMap(t *testing.T) {
	namespace := "some-namespace"
	goodCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}

	tests := []struct {
		name       string
		cm         metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "a configMap in the right namespace",
			cm:         goodCM,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
			frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			pinnipedAPIClient := conciergefake.NewSimpleClientset()
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				"concierge", // namespace for the controller
				authncache.New(),
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().JWTAuthenticators(),
				secretInformer,
				configMapInformer,
				observableInformers.WithInformer,
				frozenClock,
				logger)

			unrelated := &corev1.ConfigMap{}
			filter := observableInformers.GetFilterForInformer(configMapInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.cm, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.cm))
		})
	}
}
