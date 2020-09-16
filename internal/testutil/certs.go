// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ValidCert struct {
	t       *testing.T
	roots   *x509.CertPool
	certPEM string
	parsed  *x509.Certificate
}

// ValidateCertificate validates a certificate and provides an object for asserting properties of the certificate.
func ValidateCertificate(t *testing.T, caPEM string, certPEM string) *ValidCert {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Validate the created cert using the CA.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(caPEM)))
	opts := x509.VerifyOptions{Roots: roots}
	_, err = parsed.Verify(opts)
	require.NoError(t, err)

	return &ValidCert{
		t:       t,
		roots:   roots,
		certPEM: certPEM,
		parsed:  parsed,
	}
}

// RequireDNSName asserts that the certificate matches the provided DNS name.
func (v *ValidCert) RequireDNSName(expectDNSName string) {
	v.t.Helper()
	opts := x509.VerifyOptions{
		Roots:   v.roots,
		DNSName: expectDNSName,
	}
	_, err := v.parsed.Verify(opts)
	require.NoError(v.t, err)
	require.Contains(v.t, v.parsed.DNSNames, expectDNSName, "expected an explicit DNS SAN, not just Common Name")
}

// RequireLifetime asserts that the lifetime of the certificate matches the expected timestamps.
func (v *ValidCert) RequireLifetime(expectNotBefore time.Time, expectNotAfter time.Time, delta time.Duration) {
	v.t.Helper()
	require.WithinDuration(v.t, expectNotBefore, v.parsed.NotBefore, delta)
	require.WithinDuration(v.t, expectNotAfter, v.parsed.NotAfter, delta)
}

// RequireMatchesPrivateKey asserts that the public key in the certificate matches the provided private key.
func (v *ValidCert) RequireMatchesPrivateKey(keyPEM string) {
	v.t.Helper()
	_, err := tls.X509KeyPair([]byte(v.certPEM), []byte(keyPEM))
	require.NoError(v.t, err)
}

// CreateCertificate creates a certificate with the provided time bounds, and
// returns the PEM representation of the certificate.
//
// There is nothing very special about the certificate that it creates, just
// that it is a valid certificate that can be used for testing.
func CreateCertificate(notBefore, notAfter time.Time) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "some-common-name",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	cert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return certPEM, nil
}
