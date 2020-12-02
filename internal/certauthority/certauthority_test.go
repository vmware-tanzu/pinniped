// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package certauthority

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loadFromFiles(t *testing.T, certPath string, keyPath string) (*CA, error) {
	t.Helper()

	certPEM, err := ioutil.ReadFile(certPath)
	require.NoError(t, err)

	keyPEM, err := ioutil.ReadFile(keyPath)
	require.NoError(t, err)

	ca, err := Load(string(certPEM), string(keyPEM))
	return ca, err
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		keyPath  string
		wantErr  string
	}{
		{
			name:     "empty key",
			certPath: "./testdata/test.crt",
			keyPath:  "./testdata/empty",
			wantErr:  "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:     "invalid key",
			certPath: "./testdata/test.crt",
			keyPath:  "./testdata/invalid",
			wantErr:  "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:     "mismatched cert and key",
			certPath: "./testdata/test.crt",
			keyPath:  "./testdata/test2.key",
			wantErr:  "could not load CA: tls: private key does not match public key",
		},
		{
			name:     "multiple certs",
			certPath: "./testdata/multiple.crt",
			keyPath:  "./testdata/test.key",
			wantErr:  "invalid CA certificate: expected a single certificate, found 2 certificates",
		},
		{
			name:     "success",
			certPath: "./testdata/test.crt",
			keyPath:  "./testdata/test.key",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ca, err := loadFromFiles(t, tt.certPath, tt.keyPath)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, ca.caCertBytes)
			require.NotNil(t, ca.signer)
		})
	}
}

func TestNew(t *testing.T) {
	now := time.Now()
	got, err := New(pkix.Name{CommonName: "Test CA"}, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, got)

	// Make sure the CA certificate looks roughly like what we expect.
	caCert, err := x509.ParseCertificate(got.caCertBytes)
	require.NoError(t, err)
	require.Equal(t, "Test CA", caCert.Subject.CommonName)
	require.WithinDuration(t, now.Add(-10*time.Second), caCert.NotBefore, 10*time.Second)
	require.WithinDuration(t, now.Add(time.Minute), caCert.NotAfter, 10*time.Second)
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
			wantNotBefore:  now.Add(-10 * time.Second),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := newInternal(pkix.Name{CommonName: "Test CA"}, tt.ttl, tt.env)
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
	t.Run("success", func(t *testing.T) {
		ca := CA{caCertBytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
		got := ca.Bundle()
		require.Equal(t, "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwg=\n-----END CERTIFICATE-----\n", string(got))
	})
}

func TestPool(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ca, err := New(pkix.Name{CommonName: "test"}, 1*time.Hour)
		require.NoError(t, err)

		got := ca.Pool()
		require.Len(t, got.Subjects(), 1)
	})
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
	now := time.Date(2020, 7, 10, 12, 41, 12, 1234, time.UTC)

	realCA, err := loadFromFiles(t, "./testdata/test.crt", "./testdata/test.key")
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
					serialRNG: strings.NewReader(strings.Repeat("x", 64)),
					keygenRNG: strings.NewReader(""),
				},
			},
			wantErr: "could not generate private key: EOF",
		},
		{
			name: "invalid CA certificate",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", 64)),
					keygenRNG: strings.NewReader(strings.Repeat("x", 64)),
					clock:     func() time.Time { return now },
				},
			},
			wantErr: "could not parse CA certificate: asn1: syntax error: sequence truncated",
		},
		{
			name: "signing error",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", 64)),
					keygenRNG: strings.NewReader(strings.Repeat("x", 64)),
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
			name: "success",
			ca: CA{
				env: env{
					serialRNG: strings.NewReader(strings.Repeat("x", 64)),
					keygenRNG: strings.NewReader(strings.Repeat("x", 64)),
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
					serialRNG: strings.NewReader(strings.Repeat("x", 64)),
					keygenRNG: strings.NewReader(strings.Repeat("x", 64)),
					clock:     func() time.Time { return now },
					parseCert: x509.ParseCertificate,
				},
				caCertBytes: realCA.caCertBytes,
				signer:      realCA.signer,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.Issue(pkix.Name{CommonName: "Test Server"}, []string{"example.com"}, []net.IP{net.IPv4(1, 2, 3, 4)}, 10*time.Minute)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestIssuePEM(t *testing.T) {
	realCA, err := loadFromFiles(t, "./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err)

	certPEM, keyPEM, err := realCA.IssuePEM(pkix.Name{CommonName: "Test Server"}, []string{"example.com"}, 10*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)
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
