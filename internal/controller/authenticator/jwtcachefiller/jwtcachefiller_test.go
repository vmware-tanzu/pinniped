// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwtcachefiller

import (
	"bytes"
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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	clocktesting "k8s.io/utils/clock/testing"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/mocks/mocktokenauthenticatorcloser"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/status"
	"go.pinniped.dev/internal/testutil/tlsserver"
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

	customGroupsClaim := "my-custom-groups-claim"
	distributedGroups := []string{"some-distributed-group-1", "some-distributed-group-2"}

	goodMux := http.NewServeMux()
	goodOIDCIssuerServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		goodMux.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)

	goodMux.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, goodOIDCIssuerServer.URL, goodOIDCIssuerServer.URL+"/jwks.json")
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
	claimsWithoutSubject := jwt.Claims{
		Issuer:    goodOIDCIssuerServer.URL,
		Audience:  []string{goodAudience},
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Hour)),
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

		builder := jwt.Signed(sig).Claims(claimsWithoutSubject)

		builder = builder.Claims(map[string]interface{}{customGroupsClaim: distributedGroups})
		builder = builder.Claims(map[string]interface{}{"groups": distributedGroups})

		distributedClaimsJwt, err := builder.CompactSerialize()
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

		builder := jwt.Signed(sig).Claims(claimsWithoutSubject)

		builder = builder.Claims(map[string]interface{}{"some-other-claim": distributedGroups})

		distributedClaimsJwt, err := builder.CompactSerialize()
		require.NoError(t, err)

		_, err = w.Write([]byte(distributedClaimsJwt))
		require.NoError(t, err)
	}))

	badMuxInvalidJWKSURI := http.NewServeMux()
	badOIDCIssuerServerInvalidJWKSURI := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		badMuxInvalidJWKSURI.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	badMuxInvalidJWKSURI.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, badOIDCIssuerServerInvalidJWKSURI.URL, "https://.café   .com/café/café/café/coffee/jwks.json")
		require.NoError(t, err)
	}))

	badMuxInvalidJWKSURIScheme := http.NewServeMux()
	badOIDCIssuerServerInvalidJWKSURIScheme := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		badMuxInvalidJWKSURIScheme.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	badMuxInvalidJWKSURIScheme.Handle("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s"}`, badOIDCIssuerServerInvalidJWKSURIScheme.URL, "http://.café.com/café/café/café/coffee/jwks.json")
		require.NoError(t, err)
	}))

	goodIssuer := goodOIDCIssuerServer.URL
	badIssuerInvalidJWKSURI := badOIDCIssuerServerInvalidJWKSURI.URL
	badIssuerInvalidJWKSURIScheme := badOIDCIssuerServerInvalidJWKSURIScheme.URL
	someOtherIssuer := "https://some-other-issuer.com" // placeholder only for tests that don't get far enough to make requests
	someOtherLocalhostIssuer := "https://127.0.0.1:443/some-other-issuer"
	someOtherLocalhostIssuerParsed, err := url.Parse(someOtherLocalhostIssuer)
	require.NoError(t, err)

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	require.NoError(t, err)
	frozenMetav1Now := metav1.NewTime(nowDoesntMatter)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	someJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(goodOIDCIssuerServer.TLS),
	}
	someJWTAuthenticatorSpecWithUsernameClaim := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(goodOIDCIssuerServer.TLS),
		Claims: auth1alpha1.JWTTokenClaims{
			Username: "my-custom-username-claim",
		},
	}
	someJWTAuthenticatorSpecWithGroupsClaim := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(goodOIDCIssuerServer.TLS),
		Claims: auth1alpha1.JWTTokenClaims{
			Groups: customGroupsClaim,
		},
	}
	otherJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   someOtherIssuer,
		Audience: goodAudience,
		// Some random generated cert
		// Issuer: C=US, O=Pivotal
		// No SAN provided
		TLS: &auth1alpha1.TLSSpec{CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"},
	}
	missingTLSJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   goodIssuer,
		Audience: goodAudience,
	}
	invalidTLSJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   someOtherIssuer,
		Audience: goodAudience,
		TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "invalid base64-encoded data"},
	}

	invalidIssuerJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   "https://.café   .com/café/café/café/coffee",
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(goodOIDCIssuerServer.TLS),
	}
	invalidIssuerSchemeJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   "http://.café.com/café/café/café/coffee",
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(goodOIDCIssuerServer.TLS),
	}

	validIssuerURLButDoesNotExistJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   someOtherLocalhostIssuer,
		Audience: goodAudience,
	}
	badIssuerJWKSURIJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   badIssuerInvalidJWKSURI,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(badOIDCIssuerServerInvalidJWKSURI.TLS),
	}
	badIssuerJWKSURISchemeJWTAuthenticatorSpec := &auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   badIssuerInvalidJWKSURIScheme,
		Audience: goodAudience,
		TLS:      tlsSpecFromTLSConfig(badOIDCIssuerServerInvalidJWKSURIScheme.TLS),
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

	happyTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "valid TLS configuration",
		}
	}
	sadTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidTLSConfiguration",
			Message:            "invalid TLS configuration: illegal base64 data at input byte 7",
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
			Message:            "unable to validate; other issues present",
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
			Message:            "unable to validate; other issues present",
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
		parsed, err := url.Parse(issuer)
		require.NoError(t, err)
		return metav1.Condition{
			Type:               "DiscoveryURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidDiscoveryProbe",
			Message:            fmt.Sprintf(`could not perform oidc discovery on provider issuer: Get "%s/.well-known/openid-configuration": dial tcp %s: connect: connection refused`, issuer, parsed.Host),
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
			Message:            "unable to validate; other issues present",
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

	allHappyConditionsSuccess := func(issuer string, someTime metav1.Time, observedGeneration int64) []metav1.Condition {
		return status.SortConditionsByType([]metav1.Condition{
			happyAuthenticatorValid(someTime, observedGeneration),
			happyDiscoveryURLValid(someTime, observedGeneration),
			happyIssuerURLValid(someTime, observedGeneration),
			happyJWKSURLValid(someTime, observedGeneration),
			happyReadyCondition(someTime, observedGeneration),
			happyTLSConfigurationValid(someTime, observedGeneration),
		})
	}

	tests := []struct {
		name  string
		cache func(*testing.T, *authncache.Cache, bool)
		// syncKey is used behind the scenes to simulate the pre-existence of jwtAuthenticator(s).
		// if not provided, then the test assumes the jwtAuthenticator(s) are new Authenticator(s).
		syncKey           controllerlib.Key
		jwtAuthenticators []runtime.Object
		wantClose         bool
		// Only errors that are non-config related errors are returned from the sync loop.
		// Errors such as url.Parse of the issuer are not returned as they imply a user error.
		// Since these errors trigger a resync, we are careful only to return an error when
		// something can be automatically corrected on a retry (ie an error that might be networking).
		wantSyncLoopErr                  testutil.RequireErrorStringFunc
		wantLogs                         []map[string]any
		wantStatusConditions             []metav1.Condition
		wantStatusPhase                  auth1alpha1.JWTAuthenticatorPhase
		wantCacheEntries                 int
		wantUsernameClaim                string
		wantGroupsClaim                  string
		runTestsOnResultingAuthenticator bool
	}{
		{
			name:    "404: jwt authenticator not found will abort sync loop and not attempt to write status",
			syncKey: controllerlib.Key{Name: "test-name"},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "jwtcachefiller-controller",
					"message":   "Sync() found that the JWTAuthenticator does not exist yet or was deleted",
				},
			},
		},
		// Existing code that was never tested. We would likely have to create a server with bad clients to
		// simulate this.
		// { name: "non-404 `failed to get JWTAuthenticator` for other API server reasons" }
		{
			name:    "valid jwt authenticator with CA will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
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
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantStatusConditions:             allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
			wantStatusPhase:                  "Ready",
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "valid jwt authenticator with custom username claim will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
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
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantStatusConditions:             allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
			wantStatusPhase:                  "Ready",
			wantCacheEntries:                 1,
			wantUsernameClaim:                someJWTAuthenticatorSpecWithUsernameClaim.Claims.Username,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "valid jwt authenticator with custom groups claim will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
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
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantStatusConditions:             allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
			wantStatusPhase:                  "Ready",
			wantCacheEntries:                 1,
			wantGroupsClaim:                  someJWTAuthenticatorSpecWithGroupsClaim.Claims.Groups,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name: "updating jwt authenticator with new fields closes previous instance and will complete sync loop successfully with success conditions and ready phase",
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
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantStatusConditions:             allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
			wantStatusPhase:                  "Ready",
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name: "updating jwt authenticator with the same value does not trigger sync loop and will not update conditions or phase",
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
			wantLogs: []map[string]any{{
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "actual jwt authenticator and desired jwt authenticator are the same",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: false, // skip the tests because the authenticator left in the cache is the mock version that was added above
		},
		{
			name: "updating jwt authenticator when cache value is wrong type will complete sync loop successfully with success conditions and ready phase",
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
			wantLogs: []map[string]any{{
				"level":      "info",
				"timestamp":  "2099-08-08T13:57:36.123456Z",
				"logger":     "jwtcachefiller-controller",
				"message":    "wrong JWT authenticator type in cache",
				"actualType": "struct { authenticator.Token }",
			}, {
				"level":     "info",
				"timestamp": "2099-08-08T13:57:36.123456Z",
				"logger":    "jwtcachefiller-controller",
				"message":   "added new jwt authenticator",
				"issuer":    goodIssuer,
				"jwtAuthenticator": map[string]interface{}{
					"name": "test-name",
				},
			}},
			wantStatusConditions:             allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
			wantStatusPhase:                  "Ready",
			wantCacheEntries:                 1,
			runTestsOnResultingAuthenticator: true,
		},
		{
			name:    "TLS: valid jwt authenticator without CA will fail to cache the authenticator and will fail with failed and unknown conditions and Error phase and will enqueue a resync in case of machine error",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *missingTLSJWTAuthenticatorSpec,
				},
			},
			// no explicit logs, this is an issue of config, the user must provide TLS config for the
			// custom cert provided for this server.
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					sadReadyCondition(frozenMetav1Now, 0),
					sadDiscoveryURLValidx509(goodIssuer, frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					unknownJWKSURLValid(frozenMetav1Now, 0),
				},
			),
			wantStatusPhase:  "Error",
			wantSyncLoopErr:  testutil.WantX509UntrustedCertErrorString(`could not perform oidc discovery on provider issuer: Get "`+goodIssuer+`/.well-known/openid-configuration": %s`, "Acme Co"),
			wantCacheEntries: 0,
		},
		{
			name:    "validateTLS: invalid jwt authenticator CA will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidTLSJWTAuthenticatorSpec,
				},
			},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(someOtherIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					sadReadyCondition(frozenMetav1Now, 0),
					sadTLSConfigurationValid(frozenMetav1Now, 0),
					unknownDiscoveryURLValid(frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					unknownJWKSURLValid(frozenMetav1Now, 0),
				},
			),
			wantStatusPhase:  "Error",
			wantCacheEntries: 0,
		}, {
			name: "validateIssuer: parsing error (spec.issuer URL is invalid) will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerJWTAuthenticatorSpec,
				},
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					sadReadyCondition(frozenMetav1Now, 0),
					sadIssuerURLValidInvalid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
					unknownDiscoveryURLValid(frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					unknownJWKSURLValid(frozenMetav1Now, 0),
				},
			),
			wantStatusPhase: "Error",
		}, {
			name: "validateIssuer: parsing error (spec.issuer URL has invalid scheme, requires https) will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *invalidIssuerSchemeJWTAuthenticatorSpec,
				},
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					sadReadyCondition(frozenMetav1Now, 0),
					sadIssuerURLValidInvalidScheme("http://.café.com/café/café/café/coffee", frozenMetav1Now, 0),
					unknownDiscoveryURLValid(frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					unknownJWKSURLValid(frozenMetav1Now, 0),
				},
			),
			wantStatusPhase: "Error",
		}, {
			name: "validateProviderDiscovery: could not perform oidc discovery on provider issuer will fail sync loop and will report failed and unknown conditions and Error phase and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *validIssuerURLButDoesNotExistJWTAuthenticatorSpec,
				},
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					happyIssuerURLValid(frozenMetav1Now, 0),
					sadReadyCondition(frozenMetav1Now, 0),
					sadDiscoveryURLValidConnectionRefused(someOtherLocalhostIssuer, frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					unknownJWKSURLValid(frozenMetav1Now, 0),
				},
			),
			wantStatusPhase: "Error",
			wantSyncLoopErr: testutil.WantExactErrorString(`could not perform oidc discovery on provider issuer: Get "` + someOtherLocalhostIssuer + `/.well-known/openid-configuration": dial tcp ` + someOtherLocalhostIssuerParsed.Host + `: connect: connection refused`),
		},
		// cannot be tested currently the way the coreos lib works.
		// the constructor requires an issuer in the payload and validates the issuer matches the actual issuer,
		// which ensures the .Claims() parsing cannot fail (in the current impl)
		// { name: "validateProviderJWKSURL: could not get provider jwks_uri... ",},
		{
			name: "validateProviderJWKSURL: could not parse provider jwks_uri will fail sync loop and will report failed and unknown conditions and Error phase and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURIJWTAuthenticatorSpec,
				},
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					happyIssuerURLValid(frozenMetav1Now, 0),
					sadReadyCondition(frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					sadJWKSURLValidParseURI("https://.café   .com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
				},
			),
			wantStatusPhase: "Error",
			wantSyncLoopErr: testutil.WantExactErrorString(`could not parse provider jwks_uri: parse "https://.café   .com/café/café/café/coffee/jwks.json": invalid character " " in host name`),
		}, {
			name: "validateProviderJWKSURL: invalid scheme, requires 'https'  will fail sync loop and will report failed and unknown conditions and Error phase and will enqueue new sync",
			jwtAuthenticators: []runtime.Object{
				&auth1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: *badIssuerJWKSURISchemeJWTAuthenticatorSpec,
				},
			},
			syncKey: controllerlib.Key{Name: "test-name"},
			wantStatusConditions: status.ReplaceConditions(
				allHappyConditionsSuccess(goodIssuer, frozenMetav1Now, 0),
				[]metav1.Condition{
					happyIssuerURLValid(frozenMetav1Now, 0),
					sadReadyCondition(frozenMetav1Now, 0),
					unknownAuthenticatorValid(frozenMetav1Now, 0),
					sadJWKSURLValidScheme("http://.café.com/café/café/café/coffee/jwks.json", frozenMetav1Now, 0),
				},
			),
			wantStatusPhase: "Error",
			wantSyncLoopErr: testutil.WantExactErrorString("jwks_uri http://.café.com/café/café/café/coffee/jwks.json has invalid scheme, require 'https'"),
		},
		// cannot be tested the way we are invoking oidc.New as we don't provide enough configuration
		// knobs to actually invoke the code in a broken way.  We always give a good client, good keys, and
		// good signing algos.  In the future if we allow any of these to be configured we may have opportunity
		// to test for errors.
		// {name: "newCachedJWTAuthenticator: could not initialize oidc authenticator..." },
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset(tt.jwtAuthenticators...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			cache := authncache.New()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			if tt.cache != nil {
				tt.cache(t, cache, tt.wantClose)
			}

			controller := New(
				cache,
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().JWTAuthenticators(),
				frozenClock,
				logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantSyncLoopErr != nil {
				testutil.RequireErrorStringFromErr(t, err, tt.wantSyncLoopErr)
			} else {
				require.NoError(t, err)
			}

			actualLogLines := logLines(log.String())
			require.Equal(t, len(actualLogLines), len(tt.wantLogs), "log line count should be correct")

			for logLineNum, logLine := range actualLogLines {
				require.NotNil(t, tt.wantLogs[logLineNum], "expected log line should never be empty")
				var lineStruct map[string]any
				err := json.Unmarshal([]byte(logLine), &lineStruct)
				if err != nil {
					t.Error(err)
				}
				require.Equal(t, tt.wantLogs[logLineNum]["level"], lineStruct["level"], fmt.Sprintf("log line (%d) log level should be correct (in: %s)", logLineNum, lineStruct))

				require.Equal(t, tt.wantLogs[logLineNum]["timestamp"], lineStruct["timestamp"], fmt.Sprintf("log line (%d) timestamp should be correct (in: %s)", logLineNum, lineStruct))
				require.Equal(t, lineStruct["logger"], tt.wantLogs[logLineNum]["logger"], fmt.Sprintf("log line (%d) logger should be correct", logLineNum))
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

			if tt.jwtAuthenticators != nil {
				var jwtAuthSubject *auth1alpha1.JWTAuthenticator
				getCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				jwtAuthSubject, getErr := pinnipedAPIClient.AuthenticationV1alpha1().JWTAuthenticators().Get(getCtx, "test-name", metav1.GetOptions{})
				require.NoError(t, getErr)
				require.Equal(t, tt.wantStatusConditions, jwtAuthSubject.Status.Conditions, "status.conditions must be correct")
				require.Equal(t, tt.wantStatusPhase, jwtAuthSubject.Status.Phase, "jwt authenticator status.phase should be correct")
			}

			require.Equal(t, tt.wantCacheEntries, len(cache.Keys()), fmt.Sprintf("expected cache entries is incorrect. wanted:%d, got: %d, keys: %v", tt.wantCacheEntries, len(cache.Keys()), cache.Keys()))

			if !tt.runTestsOnResultingAuthenticator {
				return // end of test unless we wanted to run tests on the resulting authenticator from the cache
			}

			// We expected the cache to have an entry, so pull that entry from the cache and test it.
			expectedCacheKey := authncache.Key{
				APIGroup: auth1alpha1.GroupName,
				Kind:     "JWTAuthenticator",
				Name:     syncCtx.Key.Name,
			}
			cachedAuthenticator := cache.Get(expectedCacheKey)
			require.NotNil(t, cachedAuthenticator)

			// Schedule it to be closed at the end of the test.
			t.Cleanup(cachedAuthenticator.(*cachedJWTAuthenticator).Close)

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
	jwtClaims                 func(wellKnownClaims *jwt.Claims, groups *interface{}, username *string)
	jwtSignature              func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string)
	wantResponse              *authenticator.Response
	wantAuthenticated         bool
	wantErr                   testutil.RequireErrorStringFunc
	distributedGroupsClaimURL string
} {
	tests := []struct {
		name                      string
		jwtClaims                 func(wellKnownClaims *jwt.Claims, groups *interface{}, username *string)
		jwtSignature              func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string)
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
			name: "good token with good distributed groups",
			jwtClaims: func(claims *jwt.Claims, groups *interface{}, username *string) {
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
			jwtClaims: func(claims *jwt.Claims, groups *interface{}, username *string) {
			},
			distributedGroupsClaimURL: issuer + "/not_found_claim_source",
			wantErr:                   testutil.WantMatchingErrorString(`oidc: could not expand distributed claims: while getting distributed claim "` + expectedGroupsClaim + `": error while getting distributed claim JWT: 404 Not Found`),
		},
		{
			name: "distributed groups doesn't return the right claim",
			jwtClaims: func(claims *jwt.Claims, groups *interface{}, username *string) {
			},
			distributedGroupsClaimURL: issuer + "/wrong_claim_source",
			wantErr:                   testutil.WantMatchingErrorString(`oidc: could not expand distributed claims: jwt returned by distributed claim endpoint "` + issuer + `/wrong_claim_source" did not contain claim: `),
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
			wantErr: testutil.WantMatchingErrorString("oidc: parse groups claim \"" + expectedGroupsClaim + "\": json: cannot unmarshal object into Go value of type string"),
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
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: expected audience "some-audience" got \[\]`),
		},
		{
			name: "bad token with wrong audience",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Audience = []string{"wrong-audience"}
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: expected audience "some-audience" got \["wrong-audience"\]`),
		},
		{
			name: "bad token with nbf in the future",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.NotBefore = jwt.NewNumericDate(time.Date(3020, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: current time .* before the nbf \(not before\) time: 3020-.*`),
		},
		{
			name: "bad token with exp in past",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Expiry = jwt.NewNumericDate(time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC))
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: token is expired \(Token Expiry: .+`),
		},
		{
			name: "bad token without exp",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				claims.Expiry = nil
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: oidc: token is expired \(Token Expiry: .+`),
		},
		{
			name: "token does not have username claim",
			jwtClaims: func(claims *jwt.Claims, _ *interface{}, username *string) {
				*username = ""
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: parse username claims "` + expectedUsernameClaim + `": claim not present`),
		},
		{
			name: "signing key is wrong",
			jwtSignature: func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string) {
				var err error
				*key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				*algo = jose.ES256
			},
			wantErr: testutil.WantMatchingErrorString(`oidc: verify token: failed to verify signature: failed to verify id token signature`),
		},
		{
			name: "signing algo is unsupported",
			jwtSignature: func(key *interface{}, algo *jose.SignatureAlgorithm, kid *string) {
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

	builder := jwt.Signed(sig).Claims(claims)
	if groupsValue != nil {
		builder = builder.Claims(map[string]interface{}{groupsClaim: groupsValue})
	}
	if distributedGroupsClaimURL != "" {
		builder = builder.Claims(map[string]interface{}{"_claim_names": map[string]string{groupsClaim: "src1"}})
		builder = builder.Claims(map[string]interface{}{"_claim_sources": map[string]interface{}{"src1": map[string]string{"endpoint": distributedGroupsClaimURL}}})
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

	return &cachedJWTAuthenticator{
		tokenAuthenticatorCloser: tokenAuthenticatorCloser,
		spec:                     &spec,
	}
}

func logLines(logs string) []string {
	if len(logs) == 0 {
		return nil
	}

	return strings.Split(strings.TrimSpace(logs), "\n")
}
