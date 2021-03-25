// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
	"net"
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

// ValidateServerCertificate validates a certificate and provides an object for asserting properties of the certificate.
func ValidateServerCertificate(t *testing.T, caPEM string, certPEM string) *ValidCert {
	t.Helper()
	return validateCertificate(t, x509.ExtKeyUsageServerAuth, caPEM, certPEM)
}

func ValidateClientCertificate(t *testing.T, caPEM string, certPEM string) *ValidCert {
	t.Helper()
	return validateCertificate(t, x509.ExtKeyUsageClientAuth, caPEM, certPEM)
}

func validateCertificate(t *testing.T, extKeyUsage x509.ExtKeyUsage, caPEM string, certPEM string) *ValidCert {
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Validate the created cert using the CA.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(caPEM)))
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{extKeyUsage},
	}
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

func (v *ValidCert) RequireDNSNames(names []string) {
	v.t.Helper()
	require.Equal(v.t, names, v.parsed.DNSNames)
}

func (v *ValidCert) RequireEmptyDNSNames() {
	v.t.Helper()
	require.Empty(v.t, v.parsed.DNSNames)
}

func (v *ValidCert) RequireIPs(ips []net.IP) {
	v.t.Helper()
	actualIPs := v.parsed.IPAddresses
	actualIPsStrings := make([]string, len(actualIPs))
	for i := range actualIPs {
		actualIPsStrings[i] = actualIPs[i].String()
	}
	expectedIPsStrings := make([]string, len(ips))
	for i := range ips {
		expectedIPsStrings[i] = ips[i].String()
	}
	require.Equal(v.t, expectedIPsStrings, actualIPsStrings)
}

func (v *ValidCert) RequireEmptyIPs() {
	v.t.Helper()
	require.Empty(v.t, v.parsed.IPAddresses)
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

// RequireCommonName asserts that the certificate contains the provided commonName.
func (v *ValidCert) RequireCommonName(commonName string) {
	v.t.Helper()
	require.Equal(v.t, commonName, v.parsed.Subject.CommonName)
}

func (v *ValidCert) RequireOrganizations(orgs []string) {
	v.t.Helper()
	require.Equal(v.t, orgs, v.parsed.Subject.Organization)
}

// CreateCertificate creates a certificate with the provided time bounds, and returns the PEM
// representation of the certificate and its private key. The returned certificate is capable of
// signing child certificates.
func CreateCertificate(notBefore, notAfter time.Time) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "some-common-name",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	return certPEM, privateKeyPEM, nil
}
