// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict
// +build !fips_strict

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/test/testlib"
)

// TLS checks safe to run in parallel with serial tests, see main_test.go.
func TestSecureTLSPinnipedCLIToKAS_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Secure(nil)) // pinniped CLI uses ptls.Secure when talking to KAS
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
		tlsserver.AssertTLS(t, r, ptls.Default(nil)) // pinniped CLI uses ptls.Default when talking to supervisor
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

	stdout, stderr := runNmapSSLEnum(t, "127.0.0.1", 10446)

	require.Empty(t, stderr)
	require.Contains(t, stdout, getExpectedCiphers(ptls.Secure), "stdout:\n%s", stdout)
}

func TestSecureTLSSupervisor(t *testing.T) { // does not run in parallel because of the createSupervisorDefaultTLSCertificateSecretIfNeeded call
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	startKubectlPortForward(ctx, t, "10447", "443", env.SupervisorAppName+"-nodeport", env.SupervisorNamespace)

	stdout, stderr := runNmapSSLEnum(t, "127.0.0.1", 10447)

	// supervisor's cert is ECDSA
	defaultECDSAOnly := func(rootCAs *x509.CertPool) *tls.Config {
		c := ptls.Default(rootCAs)
		ciphers := make([]uint16, 0, len(c.CipherSuites)/2)
		for _, id := range c.CipherSuites {
			id := id
			if !strings.Contains(tls.CipherSuiteName(id), "_ECDSA_") {
				continue
			}
			ciphers = append(ciphers, id)
		}
		c.CipherSuites = ciphers
		return c
	}

	require.Empty(t, stderr)
	require.Contains(t, stdout, getExpectedCiphers(defaultECDSAOnly), "stdout:\n%s", stdout)
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

func runNmapSSLEnum(t *testing.T, host string, port uint16) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	version, err := exec.CommandContext(ctx, "nmap", "-V").CombinedOutput()
	require.NoError(t, err)

	versionMatches := regexp.MustCompile(`Nmap version 7\.(?P<minor>\d+)`).FindStringSubmatch(string(version))
	require.Len(t, versionMatches, 2)
	minorVersion, err := strconv.Atoi(versionMatches[1])
	require.NoError(t, err)
	require.GreaterOrEqual(t, minorVersion, 92, "nmap >= 7.92.x is required")

	var stdout, stderr bytes.Buffer
	//nolint:gosec // we are not performing malicious argument injection against ourselves
	cmd := exec.CommandContext(ctx, "nmap", "--script", "ssl-enum-ciphers",
		"-p", strconv.FormatUint(uint64(port), 10),
		host,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoErrorf(t, cmd.Run(), "stderr:\n%s\n\nstdout:\n%s\n\n", stderr.String(), stdout.String())

	return stdout.String(), stderr.String()
}

func getExpectedCiphers(configFunc ptls.ConfigFunc) string {
	config := configFunc(nil)
	secureConfig := ptls.Secure(nil)

	skip12 := config.MinVersion == secureConfig.MinVersion

	var tls12Bit, tls13Bit string

	if !skip12 {
		sort.SliceStable(config.CipherSuites, func(i, j int) bool {
			a := tls.CipherSuiteName(config.CipherSuites[i])
			b := tls.CipherSuiteName(config.CipherSuites[j])

			ok1 := strings.Contains(a, "_ECDSA_")
			ok2 := strings.Contains(b, "_ECDSA_")

			if ok1 && ok2 {
				return false
			}

			return ok1
		})

		var s strings.Builder
		for i, id := range config.CipherSuites {
			s.WriteString(fmt.Sprintf(tls12Item, tls.CipherSuiteName(id)))
			if i == len(config.CipherSuites)-1 {
				break
			}
			s.WriteString("\n")
		}
		tls12Bit = fmt.Sprintf(tls12Base, s.String())
	}

	var s strings.Builder
	for i, id := range secureConfig.CipherSuites {
		s.WriteString(fmt.Sprintf(tls13Item, strings.Replace(tls.CipherSuiteName(id), "TLS_", "TLS_AKE_WITH_", 1)))
		if i == len(secureConfig.CipherSuites)-1 {
			break
		}
		s.WriteString("\n")
	}
	tls13Bit = fmt.Sprintf(tls13Base, s.String())

	return fmt.Sprintf(baseItem, tls12Bit, tls13Bit)
}

const (
	// this surrounds the tls 1.2 and 1.3 text in a way that guarantees that other TLS versions are not supported.
	baseItem = `/tcp open  unknown
| ssl-enum-ciphers: %s%s
|_  least strength: A

Nmap done: 1 IP address (1 host up) scanned in`

	// the "cipher preference: client" bit a bug in nmap.
	// https://github.com/nmap/nmap/issues/1691#issuecomment-536919978
	tls12Base = `
|   TLSv1.2: 
|     ciphers: 
%s
|     compressors: 
|       NULL
|     cipher preference: client`

	tls13Base = `
|   TLSv1.3: 
|     ciphers: 
%s
|     cipher preference: server`

	tls12Item = `|       %s (secp256r1) - A`
	tls13Item = `|       %s (ecdh_x25519) - A`
)
