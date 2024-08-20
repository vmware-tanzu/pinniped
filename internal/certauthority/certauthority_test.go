// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package certauthority

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil"
)

var (
	//go:embed testdata/empty
	empty string
	//go:embed testdata/invalid
	invalid string
	//go:embed testdata/multiple.crt
	multiple string
	//go:embed testdata/test.crt
	testCert string
	//go:embed testdata/test.key
	testKey string
	//go:embed testdata/test2.key
	testKey2 string
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr string
		test    []byte
	}{
		{
			name:    "empty key",
			cert:    testCert,
			key:     empty,
			wantErr: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:    "invalid key",
			cert:    testCert,
			key:     invalid,
			wantErr: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:    "mismatched cert and key",
			cert:    testCert,
			key:     testKey2,
			wantErr: "could not load CA: tls: private key does not match public key",
		},
		{
			name:    "multiple certs",
			cert:    multiple,
			key:     testKey,
			wantErr: "invalid CA certificate: expected a single certificate, found 2 certificates",
		},
		{
			name: "success",
			cert: testCert,
			key:  testKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := Load(tt.cert, tt.key)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, ca.caCertBytes)
			require.NotNil(t, ca.signer)
			require.Nil(t, ca.privateKey) // this struct field is only used for CA's created by New()
		})
	}
}

func TestNew(t *testing.T) {
	now := time.Now()
	ca, err := New("Test CA", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, ca)

	// Make sure the CA certificate looks roughly like what we expect.
	caCert, err := x509.ParseCertificate(ca.caCertBytes)
	require.NoError(t, err)
	require.Equal(t, "Test CA", caCert.Subject.CommonName)
	require.WithinDuration(t, now.Add(-5*time.Minute), caCert.NotBefore, 10*time.Second)
	require.WithinDuration(t, now.Add(time.Minute), caCert.NotAfter, 10*time.Second)

	require.NotNil(t, ca.privateKey)
}

func TestNewInternal(t *testing.T) {
	now := time.Date(2020, 7, 10, 12, 41, 12, 1234, time.UTC)

	tests := []struct {
		name           string
		ttl            time.Duration
		env            env
		wantErr        string
		wantCommonName string
		wantNotBefore  time.Time
		wantNotAfter   time.Time
	}{
		{
			name: "failed to generate CA serial",
			env: env{
				serialRNG:  strings.NewReader(""),
				keygenRNG:  strings.NewReader(""),
				signingRNG: strings.NewReader(""),
			},
			wantErr: "could not generate CA serial: EOF",
		},
		{
			name: "failed to generate CA key",
			env: env{
				serialRNG:  strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG:  strings.NewReader(""),
				signingRNG: strings.NewReader(""),
			},
			wantErr: "could not generate CA private key: EOF",
		},
		{
			name: "failed to self-sign",
			env: env{
				serialRNG:  strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG:  strings.NewReader(strings.Repeat("y", 64)),
				signingRNG: strings.NewReader(""),
				clock:      func() time.Time { return now },
			},
			wantErr: "could not issue CA certificate: EOF",
		},
		{
			name: "success",
			ttl:  time.Minute,
			env: env{
				serialRNG:  strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG:  strings.NewReader(strings.Repeat("y", 64)),
				signingRNG: strings.NewReader(strings.Repeat("z", 64)),
				clock:      func() time.Time { return now },
			},
			wantCommonName: "Test CA",
			wantNotAfter:   now.Add(time.Minute),
			wantNotBefore:  now.Add(-5 * time.Minute),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newInternal("Test CA", tt.ttl, tt.env)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)

			// Make sure the CA certificate looks roughly like what we expect.
			caCert, err := x509.ParseCertificate(got.caCertBytes)
			require.NoError(t, err)
			require.Equal(t, tt.wantCommonName, caCert.Subject.CommonName)
			require.Equal(t, tt.wantNotAfter.Unix(), caCert.NotAfter.Unix())
			require.Equal(t, tt.wantNotBefore.Unix(), caCert.NotBefore.Unix())
		})
	}
}

func TestBundle(t *testing.T) {
	ca := CA{caCertBytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	certPEM := ca.Bundle()
	require.Equal(t, "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwg=\n-----END CERTIFICATE-----\n", string(certPEM))
}

func TestPrivateKeyToPEM(t *testing.T) {
	ca, err := New("Test CA", time.Hour)
	require.NoError(t, err)
	keyPEM, err := ca.PrivateKeyToPEM()
	require.NoError(t, err)
	require.Regexp(t, "(?s)-----BEGIN EC "+"PRIVATE KEY-----\n.*\n-----END EC PRIVATE KEY-----", string(keyPEM))
	certPEM := ca.Bundle()
	// Check that the public and private keys work together.
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	reloaded, err := Load(string(certPEM), string(keyPEM))
	require.NoError(t, err)
	_, err = reloaded.PrivateKeyToPEM()
	require.EqualError(t, err, "no private key data (did you try to use this after Load?)")
}

func TestPool(t *testing.T) {
	ca, err := New("test", 1*time.Hour)
	require.NoError(t, err)

	expectedPool := x509.NewCertPool()
	expectedPool.AppendCertsFromPEM(ca.Bundle())

	require.True(t, expectedPool.Equal(ca.Pool()))
}

type errSigner struct {
	pubkey crypto.PublicKey
	err    error
}

func (e *errSigner) Public() crypto.PublicKey { return e.pubkey }

func (e *errSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, e.err
}

func TestIssue(t *testing.T) {
	const numRandBytes = 64 * 2 // each call to issue a cert will consume 64 bytes from the reader

	now := time.Date(2020, 7, 10, 12, 41, 12, 1234, time.UTC)

	realCA, err := Load(testCert, testKey)
	require.NoError(t, err)

	tests := []struct {
		name    string
		ca      CA
		wantErr string
	}{
		{
			name: "failed to generate serial",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(""),
				},
			},
			wantErr: "could not generate serial number for certificate: EOF",
		},
		{
			name: "failed to generate keypair",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					keygenRNG: strings.NewReader(""),
				},
			},
			wantErr: "could not generate private key: EOF",
		},
		{
			name: "invalid CA certificate",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					keygenRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					clock:     func() time.Time { return now },
				},
			},
			wantErr: "could not parse CA certificate: x509: malformed certificate",
		},
		{
			name: "signing error",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					keygenRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					clock:     func() time.Time { return now },
				},
				caCertBytes: realCA.caCertBytes,
				signer: &errSigner{
					pubkey: realCA.signer.Public(),
					err:    fmt.Errorf("some signer error"),
				},
			},
			wantErr: "could not sign certificate: some signer error",
		},
		{
			name: "parse certificate error",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					keygenRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					clock:     func() time.Time { return now },
					parseCert: func(_ []byte) (*x509.Certificate, error) {
						return nil, fmt.Errorf("some parse certificate error")
					},
				},
				caCertBytes: realCA.caCertBytes,
				signer:      realCA.signer,
			},
			wantErr: "could not parse certificate: some parse certificate error",
		},
		{
			name: "success",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					keygenRNG: strings.NewReader(strings.Repeat("x", numRandBytes)),
					clock:     func() time.Time { return now },
					parseCert: x509.ParseCertificate,
				},
				caCertBytes: realCA.caCertBytes,
				signer:      realCA.signer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.IssueServerCert([]string{"example.com"}, []net.IP{net.IPv4(1, 2, 3, 4)}, 10*time.Minute)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
			}
			got, err = tt.ca.IssueClientCert("test-user", []string{"group1", "group2"}, 10*time.Minute)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
			}
		})
	}
}

func TestToPEM(t *testing.T) {
	realCert, err := tls.LoadX509KeyPair("./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err)

	t.Run("error from input", func(t *testing.T) {
		certPEM, keyPEM, err := toPEM(nil, fmt.Errorf("some error"))
		require.EqualError(t, err, "some error")
		require.Nil(t, certPEM)
		require.Nil(t, keyPEM)
	})

	t.Run("invalid private key", func(t *testing.T) {
		cert := realCert
		cert.PrivateKey = nil
		certPEM, keyPEM, err := toPEM(&cert, nil)
		require.EqualError(t, err, "failed to marshal private key into PKCS8: x509: unknown key type while marshaling PKCS#8: <nil>")
		require.Nil(t, certPEM)
		require.Nil(t, keyPEM)
	})

	t.Run("success", func(t *testing.T) {
		certPEM, keyPEM, err := toPEM(&realCert, nil)
		require.NoError(t, err)
		require.NotEmpty(t, certPEM)
		require.NotEmpty(t, keyPEM)
	})
}

func TestIssueMethods(t *testing.T) {
	// One CA can be used to issue both kinds of certs.
	ca, err := New("Test CA", time.Hour)
	require.NoError(t, err)

	ttl := 121 * time.Hour

	t.Run("client certs", func(t *testing.T) {
		user := "test-username"
		groups := []string{"group1", "group2"}

		clientCert, err := ca.IssueClientCert(user, groups, ttl)
		require.NoError(t, err)
		certPEM, keyPEM, err := ToPEM(clientCert)
		require.NoError(t, err)
		validateClientCert(t, ca.Bundle(), certPEM, keyPEM, user, groups, ttl)

		certPEM, keyPEM, err = ca.IssueClientCertPEM(user, groups, ttl)
		require.NoError(t, err)
		validateClientCert(t, ca.Bundle(), certPEM, keyPEM, user, groups, ttl)

		certPEM, keyPEM, err = ca.IssueClientCertPEM(user, nil, ttl)
		require.NoError(t, err)
		validateClientCert(t, ca.Bundle(), certPEM, keyPEM, user, nil, ttl)

		certPEM, keyPEM, err = ca.IssueClientCertPEM(user, []string{}, ttl)
		require.NoError(t, err)
		validateClientCert(t, ca.Bundle(), certPEM, keyPEM, user, nil, ttl)

		certPEM, keyPEM, err = ca.IssueClientCertPEM("", []string{}, ttl)
		require.NoError(t, err)
		validateClientCert(t, ca.Bundle(), certPEM, keyPEM, "", nil, ttl)
	})

	t.Run("server certs", func(t *testing.T) {
		dnsNames := []string{"example.com", "pinniped.dev"}
		ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("1.2.3.4")}

		serverCert, err := ca.IssueServerCert(dnsNames, ips, ttl)
		require.NoError(t, err)
		certPEM, keyPEM, err := ToPEM(serverCert)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, dnsNames, ips, ttl)

		certPEM, keyPEM, err = ca.IssueServerCertPEM(dnsNames, ips, ttl)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, dnsNames, ips, ttl)

		certPEM, keyPEM, err = ca.IssueServerCertPEM(nil, ips, ttl)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, nil, ips, ttl)

		certPEM, keyPEM, err = ca.IssueServerCertPEM(dnsNames, nil, ttl)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, dnsNames, nil, ttl)

		certPEM, keyPEM, err = ca.IssueServerCertPEM([]string{}, ips, ttl)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, nil, ips, ttl)

		certPEM, keyPEM, err = ca.IssueServerCertPEM(dnsNames, []net.IP{}, ttl)
		require.NoError(t, err)
		validateServerCert(t, ca.Bundle(), certPEM, keyPEM, dnsNames, nil, ttl)
	})
}

func validateClientCert(t *testing.T, caBundle []byte, certPEM []byte, keyPEM []byte, expectedUser string, expectedGroups []string, expectedTTL time.Duration) {
	const fudgeFactor = 10 * time.Second
	v := testutil.ValidateClientCertificate(t, string(caBundle), string(certPEM))
	v.RequireLifetime(time.Now(), time.Now().Add(expectedTTL), certBackdate+fudgeFactor)
	v.RequireMatchesPrivateKey(string(keyPEM))
	v.RequireCommonName(expectedUser)
	v.RequireOrganizations(expectedGroups)
	v.RequireEmptyDNSNames()
	v.RequireEmptyIPs()
}

func validateServerCert(t *testing.T, caBundle []byte, certPEM []byte, keyPEM []byte, expectedDNSNames []string, expectedIPs []net.IP, expectedTTL time.Duration) {
	const fudgeFactor = 10 * time.Second
	v := testutil.ValidateServerCertificate(t, string(caBundle), string(certPEM))
	v.RequireLifetime(time.Now(), time.Now().Add(expectedTTL), certBackdate+fudgeFactor)
	v.RequireMatchesPrivateKey(string(keyPEM))
	v.RequireCommonName("")
	v.RequireDNSNames(expectedDNSNames)
	v.RequireIPs(expectedIPs)
}
