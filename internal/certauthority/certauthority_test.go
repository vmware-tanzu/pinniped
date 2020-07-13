/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package certauthority

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	now := time.Date(2020, 7, 10, 12, 41, 12, 1234, time.UTC)

	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name: "error option",
			opts: []Option{func(ca *CA) error {
				return fmt.Errorf("some error")
			}},
			wantErr: "some error",
		},
		{
			name: "failed to generate CA serial",
			opts: []Option{func(ca *CA) error {
				ca.serialRNG = strings.NewReader("")
				ca.keygenRNG = strings.NewReader("")
				ca.signingRNG = strings.NewReader("")
				return nil
			}},
			wantErr: "could not generate CA serial: EOF",
		},
		{
			name: "failed to generate CA key",
			opts: []Option{func(ca *CA) error {
				ca.serialRNG = strings.NewReader(strings.Repeat("x", 64))
				ca.keygenRNG = strings.NewReader("")
				return nil
			}},
			wantErr: "could not generate CA private key: EOF",
		},
		{
			name: "failed to self-sign",
			opts: []Option{func(ca *CA) error {
				ca.serialRNG = strings.NewReader(strings.Repeat("x", 64))
				ca.keygenRNG = strings.NewReader(strings.Repeat("y", 64))
				ca.signingRNG = strings.NewReader("")
				return nil
			}},
			wantErr: "could not issue CA certificate: EOF",
		},
		{
			name: "success",
			opts: []Option{func(ca *CA) error {
				ca.serialRNG = strings.NewReader(strings.Repeat("x", 64))
				ca.keygenRNG = strings.NewReader(strings.Repeat("y", 64))
				ca.signingRNG = strings.NewReader(strings.Repeat("z", 64))
				ca.clock = func() time.Time { return now }
				return nil
			}},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(pkix.Name{CommonName: "Test CA"}, tt.opts...)
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
			require.Equal(t, "Test CA", caCert.Subject.CommonName)
			require.Equal(t, now.Add(100*365*24*time.Hour).Unix(), caCert.NotAfter.Unix())
			require.Equal(t, now.Add(-1*time.Minute).Unix(), caCert.NotBefore.Unix())
		})
	}
}

type errWriter struct {
	err error
}

func (e *errWriter) Write(p []byte) (n int, err error) { return 0, e.err }

func TestWriteBundle(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		ca := CA{}
		out := errWriter{fmt.Errorf("some error")}
		require.EqualError(t, ca.WriteBundle(&out), "could not encode CA certificate to PEM: some error")
	})

	t.Run("empty", func(t *testing.T) {
		ca := CA{}
		var out bytes.Buffer
		require.NoError(t, ca.WriteBundle(&out))
		require.Equal(t, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", out.String())
	})

	t.Run("success", func(t *testing.T) {
		ca := CA{caCertBytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
		var out bytes.Buffer
		require.NoError(t, ca.WriteBundle(&out))
		require.Equal(t, "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwg=\n-----END CERTIFICATE-----\n", out.String())
	})
}

func TestBundle(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ca := CA{caCertBytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
		got, err := ca.Bundle()
		require.NoError(t, err)
		require.Equal(t, "-----BEGIN CERTIFICATE-----\nAQIDBAUGBwg=\n-----END CERTIFICATE-----\n", string(got))
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

	realCA, err := New(pkix.Name{CommonName: "Test CA"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		ca      CA
		wantErr string
	}{
		{
			name: "failed to generate serial",
			ca: CA{
				serialRNG: strings.NewReader(""),
			},
			wantErr: "could not generate serial number for certificate: EOF",
		},
		{
			name: "failed to generate keypair",
			ca: CA{
				serialRNG: strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG: strings.NewReader(""),
			},
			wantErr: "could not generate private key: EOF",
		},
		{
			name: "invalid CA certificate",
			ca: CA{
				serialRNG: strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG: strings.NewReader(strings.Repeat("x", 64)),
				clock:     func() time.Time { return now },
			},
			wantErr: "could not parse CA certificate: asn1: syntax error: sequence truncated",
		},
		{
			name: "signing error",
			ca: CA{
				serialRNG:   strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG:   strings.NewReader(strings.Repeat("x", 64)),
				clock:       func() time.Time { return now },
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
				serialRNG:   strings.NewReader(strings.Repeat("x", 64)),
				keygenRNG:   strings.NewReader(strings.Repeat("x", 64)),
				clock:       func() time.Time { return now },
				caCertBytes: realCA.caCertBytes,
				signer:      realCA.signer,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ca.Issue(pkix.Name{CommonName: "Test Server"}, []string{"example.com"}, 10*time.Minute)
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
