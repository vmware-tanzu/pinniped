// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build fips_strict
// +build fips_strict

package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/test/testlib"
)

// In fips-only mode, we don't explicitly set the cipher suites
// in the tls config, we just let them default.
// The expected cipher suites should belong to this
// hard-coded list, copied from here:
// https://github.com/golang/go/blob/dev.boringcrypto/src/crypto/tls/boring.go.
var defaultCipherSuitesFIPS = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// This test mirrors securetls_test.go, but adapted for fips mode.
// e.g. checks for only TLS 1.2 ciphers and checks for the
// list of fips-approved ciphers above.
// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSPinnipedCLIToKAS_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)
	t.Log("testing FIPs tls config")

	server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// pinniped CLI uses ptls.Secure when talking to KAS,
		// although the distinction doesn't matter much in FIPs mode because
		// each of the configs is a wrapper for the same base FIPs config.
		secure := ptls.Secure(nil)
		secure.CipherSuites = defaultCipherSuitesFIPS
		tlsserver.AssertTLSConfig(t, r, secure)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"kind":"TokenCredentialRequest","apiVersion":"login.concierge.pinniped.dev/v1alpha1",`+
			`"status":{"credential":{"token":"some-fancy-token"}}}`)
	}), tlsserver.RecordTLSHello)

	ca := tlsserver.TLSTestServerCA(server)

	pinnipedExe := testlib.PinnipedCLIPath(t)

	stdout, stderr := runPinnipedCLI(t, nil, pinnipedExe, "login", "static",
		"--token", "does-not-matter",
		"--concierge-authenticator-type", "webhook",
		"--concierge-authenticator-name", "does-not-matter",
		"--concierge-ca-bundle-data", base64.StdEncoding.EncodeToString(ca),
		"--concierge-endpoint", server.URL,
		"--enable-concierge",
		"--credential-cache", "",
	)

	require.Empty(t, stderr)
	require.Equal(t, `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1",`+
		`"spec":{"interactive":false},"status":{"expirationTimestamp":null,"token":"some-fancy-token"}}
`, stdout)
}

// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSPinnipedCLIToSupervisor_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// pinniped CLI uses ptls.Default when talking to supervisor,
		// although the distinction doesn't matter much in FIPs mode because
		// each of the configs is a wrapper for the same base FIPs config.
		defaultTLS := ptls.Default(nil)
		defaultTLS.CipherSuites = defaultCipherSuitesFIPS
		tlsserver.AssertTLSConfig(t, r, defaultTLS)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"issuer":"https://not-a-good-issuer"}`)
	}), tlsserver.RecordTLSHello)

	ca := tlsserver.TLSTestServerCA(server)

	pinnipedExe := testlib.PinnipedCLIPath(t)

	stdout, stderr := runPinnipedCLI(&fakeT{T: t}, nil, pinnipedExe, "login", "oidc",
		"--ca-bundle-data", base64.StdEncoding.EncodeToString(ca),
		"--issuer", server.URL,
		"--credential-cache", "",
		"--upstream-identity-provider-flow", "cli_password",
		"--upstream-identity-provider-name", "does-not-matter",
		"--upstream-identity-provider-type", "oidc",
	)

	require.Equal(t, `Error: could not complete Pinniped login: could not perform OIDC discovery for "`+
		server.URL+`": oidc: issuer did not match the issuer returned by provider, expected "`+
		server.URL+`" got "https://not-a-good-issuer"
`, stderr)
	require.Empty(t, stdout)
}

// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSConciergeAggregatedAPI_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startKubectlPortForward(cancelCtx, t, "10446", "443", env.ConciergeAppName+"-api", env.ConciergeNamespace)

	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10446)

	require.Empty(t, stderr)
	secure := ptls.Secure(nil)
	secure.CipherSuites = defaultCipherSuitesFIPS
	require.Contains(t, stdout, testlib.GetExpectedCiphers(secure, "server"), "stdout:\n%s", stdout)
}

func TestSecureTLSSupervisor(t *testing.T) { // does not run in parallel because of the createSupervisorDefaultTLSCertificateSecretIfNeeded call
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startKubectlPortForward(ctx, t, "10447", "443", env.SupervisorAppName+"-nodeport", env.SupervisorNamespace)

	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10447)

	// supervisor's cert is ECDSA
	defaultECDSAOnly := ptls.Default(nil)
	ciphers := make([]uint16, 0, len(defaultCipherSuitesFIPS)/3)
	for _, id := range defaultCipherSuitesFIPS {
		id := id
		if !strings.Contains(tls.CipherSuiteName(id), "_ECDSA_") {
			continue
		}
		ciphers = append(ciphers, id)
	}
	defaultECDSAOnly.CipherSuites = ciphers

	require.Empty(t, stderr)
	require.Contains(t, stdout, testlib.GetExpectedCiphers(defaultECDSAOnly, "server"), "stdout:\n%s", stdout)
}

type fakeT struct {
	*testing.T
}

func (t *fakeT) FailNow() {
	t.Errorf("fakeT ignored FailNow")
}

func (t *fakeT) Errorf(format string, args ...interface{}) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("reporting previously ignored errors since main test failed:\n"+format, args...)
	})
}
