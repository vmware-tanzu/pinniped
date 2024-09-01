// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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

// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSPinnipedCLIToKAS_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	server, serverCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// pinniped CLI uses ptls.Secure when talking to KAS
		// in FIPS mode the distinction doesn't matter much because
		// each of the configs is a wrapper for the same base FIPS config
		tlsserver.AssertTLS(t, r, ptls.Secure)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"kind":"TokenCredentialRequest","apiVersion":"login.concierge.pinniped.dev/v1alpha1",`+
			`"status":{"credential":{"token":"some-fancy-token"}}}`)
	}), tlsserver.RecordTLSHello)

	pinnipedExe := testlib.PinnipedCLIPath(t)

	stdout, stderr := runPinnipedCLI(t, nil, pinnipedExe, "login", "static",
		"--token", "does-not-matter",
		"--concierge-authenticator-type", "webhook",
		"--concierge-authenticator-name", "does-not-matter",
		"--concierge-ca-bundle-data", base64.StdEncoding.EncodeToString(serverCA),
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

	server, serverCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// pinniped CLI uses ptls.Default when talking to supervisor
		// in FIPS mode the distinction doesn't matter much because
		// each of the configs is a wrapper for the same base FIPS config
		tlsserver.AssertTLS(t, r, ptls.Default)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"issuer":"https://not-a-good-issuer"}`)
	}), tlsserver.RecordTLSHello)

	pinnipedExe := testlib.PinnipedCLIPath(t)

	stdout, stderr := runPinnipedCLI(&fakeT{T: t}, nil, pinnipedExe, "login", "oidc",
		"--ca-bundle-data", base64.StdEncoding.EncodeToString(serverCA),
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
	require.Contains(t, stdout, testlib.GetExpectedCiphers(ptls.Secure(nil), testlib.DefaultCipherSuitePreference), "stdout:\n%s", stdout)
}

// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSSupervisorAggregatedAPI_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startKubectlPortForward(cancelCtx, t, "10447", "443", env.SupervisorAppName+"-api", env.SupervisorNamespace)

	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10447)

	require.Empty(t, stderr)
	require.Contains(t, stdout, testlib.GetExpectedCiphers(ptls.Secure(nil), testlib.DefaultCipherSuitePreference), "stdout:\n%s", stdout)
}

func TestSecureTLSSupervisor(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	supervisorIssuer := testlib.NewSupervisorIssuer(t, env.SupervisorHTTPSAddress)

	serviceSuffix := "-nodeport"
	if supervisorIssuer.IsIPAddress() {
		// Then there's no nodeport service to connect to, it's a load balancer service!
		serviceSuffix = "-loadbalancer"
	}

	startKubectlPortForward(ctx, t, "10448", "443", env.SupervisorAppName+serviceSuffix, env.SupervisorNamespace)

	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10448)

	// The Supervisor's auto-generated bootstrap TLS cert is ECDSA, so we think that only the ECDSA ciphers
	// will be available on the server for TLS 1.2. Therefore, filter the list of expected ciphers to only
	// include the ECDSA ciphers.
	defaultECDSAOnly := ptls.Default(nil)
	ciphers := make([]uint16, 0, len(defaultECDSAOnly.CipherSuites)/2)
	for _, id := range defaultECDSAOnly.CipherSuites {
		if !strings.Contains(tls.CipherSuiteName(id), "_ECDSA_") {
			continue
		}
		ciphers = append(ciphers, id)
	}
	defaultECDSAOnly.CipherSuites = ciphers

	require.Empty(t, stderr)
	require.Contains(t, stdout, testlib.GetExpectedCiphers(defaultECDSAOnly, testlib.DefaultCipherSuitePreference), "stdout:\n%s", stdout)
}

type fakeT struct {
	*testing.T
}

func (t *fakeT) FailNow() {
	t.Errorf("fakeT ignored FailNow")
}

func (t *fakeT) Errorf(format string, args ...any) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Logf("reporting previously ignored errors since main test failed:\n"+format, args...)
	})
}
