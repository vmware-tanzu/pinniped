// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package certauthority implements a simple x509 certificate authority suitable for use in an aggregated API service.
package certauthority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"go.pinniped.dev/internal/cert"
	"go.pinniped.dev/internal/constable"
)

// certBackdate is the amount of time before time.Now() that will be used to set
// a certificate's NotBefore field.  We use the same hard coded and unconfigurable
// backdate value as used by the Kubernetes controller manager certificate signer:
// https://github.com/kubernetes/kubernetes/blob/68d646a101005e95379d84160adf01d146bdd149/pkg/controller/certificates/signer/signer.go#L199
const certBackdate = 5 * time.Minute

type env struct {
	// secure random number generators for various steps (usually crypto/rand.Reader, but broken out here for tests).
	serialRNG  io.Reader
	keygenRNG  io.Reader
	signingRNG io.Reader

	// clock tells the current time (usually time.Now(), but broken out here for tests).
	clock func() time.Time

	// parse function to parse an ASN.1 byte slice into a x509 struct (normally x509.ParseCertificate)
	parseCert func([]byte) (*x509.Certificate, error)
}

// CA holds the state for a simple x509 certificate authority suitable for use in an aggregated API service.
type CA struct {
	// caCertBytes is the DER-encoded certificate for the current CA.
	caCertBytes []byte

	// signer is the private key for the current CA.
	signer crypto.Signer

	// privateKey is the same private key represented by signer, but in a format which allows export.
	// It is only set by New, not by Load, since Load can handle various types of PrivateKey but New
	// only needs to create keys of type ecdsa.PrivateKey.
	privateKey *ecdsa.PrivateKey

	// env is our reference to the outside world (clocks and random number generation).
	env env
}

// secureEnv is the "real" environment using secure RNGs and the real system clock.
func secureEnv() env {
	return env{
		serialRNG:  rand.Reader,
		keygenRNG:  rand.Reader,
		signingRNG: rand.Reader,
		clock:      time.Now,
		parseCert:  x509.ParseCertificate,
	}
}

// ErrInvalidCACertificate is returned when the contents of the loaded CA certificate do not meet our assumptions.
const ErrInvalidCACertificate = constable.Error("invalid CA certificate")

// Load a certificate authority from an existing certificate and private key (in PEM format).
func Load(certPEM string, keyPEM string) (*CA, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("could not load CA: %w", err)
	}
	if certCount := len(cert.Certificate); certCount != 1 {
		return nil, fmt.Errorf("%w: expected a single certificate, found %d certificates", ErrInvalidCACertificate, certCount)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse key pair as x509 cert: %w", err)
	}
	if !x509Cert.IsCA {
		return nil, fmt.Errorf("%w: passed in key pair is not a CA", ErrInvalidCACertificate)
	}
	return &CA{
		caCertBytes: cert.Certificate[0],
		signer:      cert.PrivateKey.(crypto.Signer),
		env:         secureEnv(),
	}, nil
}

// New generates a fresh certificate authority with the given Common Name and TTL.
func New(commonName string, ttl time.Duration) (*CA, error) {
	return newInternal(commonName, ttl, secureEnv())
}

// newInternal is the internal guts of New, broken out for easier testing.
func newInternal(commonName string, ttl time.Duration, env env) (*CA, error) {
	ca := CA{env: env}
	// Generate a random serial for the CA
	serialNumber, err := randomSerial(env.serialRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate CA serial: %w", err)
	}

	// Generate a new P256 keypair.
	ca.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), env.keygenRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate CA private key: %w", err)
	}
	ca.signer = ca.privateKey

	// Make a CA certificate valid for some ttl and backdated by some amount.
	now := env.clock()
	notBefore := now.Add(-certBackdate)
	notAfter := now.Add(ttl)

	// Create CA cert template
	caTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Self-sign the CA to get the DER certificate.
	caCertBytes, err := x509.CreateCertificate(env.signingRNG, &caTemplate, &caTemplate, &ca.privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not issue CA certificate: %w", err)
	}
	ca.caCertBytes = caCertBytes
	return &ca, nil
}

// Bundle returns the current CA signing bundle in concatenated PEM format.
func (c *CA) Bundle() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caCertBytes})
}

// PrivateKeyToPEM returns the current CA private key in PEM format, if this CA was constructed by New.
func (c *CA) PrivateKeyToPEM() ([]byte, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("no private key data (did you try to use this after Load?)")
	}
	derKey, err := x509.MarshalECPrivateKey(c.privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey}), nil
}

// Pool returns the current CA signing bundle as a *x509.CertPool.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c.Bundle())
	return pool
}

// IssueClientCert issues a new client certificate with username and groups included in the Kube-style
// certificate subject for the given identity and duration.
func (c *CA) IssueClientCert(username string, groups []string, ttl time.Duration) (*tls.Certificate, error) {
	return c.issueCert(x509.ExtKeyUsageClientAuth, pkix.Name{CommonName: username, Organization: groups}, nil, nil, ttl)
}

// IssueServerCert issues a new server certificate for the given identity and duration.
// The dnsNames and ips are each optional, but at least one of them should be specified.
func (c *CA) IssueServerCert(dnsNames []string, ips []net.IP, ttl time.Duration) (*tls.Certificate, error) {
	return c.issueCert(x509.ExtKeyUsageServerAuth, pkix.Name{}, dnsNames, ips, ttl)
}

// IssueClientCertPEM is similar to IssueClientCert, but returns the new cert as a pair of PEM-formatted byte slices
// for the certificate and private key, along with the notBefore and notAfter values.
func (c *CA) IssueClientCertPEM(username string, groups []string, ttl time.Duration) (*cert.PEM, error) {
	return toPEM(c.IssueClientCert(username, groups, ttl))
}

// IssueServerCertPEM is similar to IssueServerCert, but returns the new cert as a pair of PEM-formatted byte slices
// for the certificate and private key, along with the notBefore and notAfter values.
func (c *CA) IssueServerCertPEM(dnsNames []string, ips []net.IP, ttl time.Duration) (*cert.PEM, error) {
	return toPEM(c.IssueServerCert(dnsNames, ips, ttl))
}

func (c *CA) issueCert(extKeyUsage x509.ExtKeyUsage, subject pkix.Name, dnsNames []string, ips []net.IP, ttl time.Duration) (*tls.Certificate, error) {
	// Choose a random 128-bit serial number.
	serialNumber, err := randomSerial(c.env.serialRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate serial number for certificate: %w", err)
	}

	// Generate a new P256 keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), c.env.keygenRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	// Make a CA caCert valid for the requested TTL and backdated by some amount.
	now := c.env.clock()
	notBefore := now.Add(-certBackdate)
	notAfter := now.Add(ttl)

	// Parse the DER encoded certificate to get a x509.Certificate.
	caCert, err := x509.ParseCertificate(c.caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse CA certificate: %w", err)
	}

	// Sign a cert, getting back the DER-encoded certificate bytes.
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{extKeyUsage},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("could not sign certificate: %w", err)
	}

	// Parse the DER encoded certificate back out into an *x509.Certificate.
	newCert, err := c.env.parseCert(certBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	// Return the new certificate.
	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		Leaf:        newCert,
		PrivateKey:  privateKey,
	}, nil
}

func toPEM(certificate *tls.Certificate, err error) (*cert.PEM, error) {
	// If the wrapped IssueServerCert() returned an error, pass it back.
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := ToPEM(certificate)
	if err != nil {
		return nil, err
	}

	return &cert.PEM{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		NotBefore: certificate.Leaf.NotBefore,
		NotAfter:  certificate.Leaf.NotAfter,
	}, nil
}

// ToPEM encodes a tls.Certificate into a private key PEM and a cert chain PEM.
func ToPEM(cert *tls.Certificate) ([]byte, []byte, error) {
	// Encode the certificate(s) to PEM.
	certPEMBlocks := make([][]byte, 0, len(cert.Certificate))
	for _, c := range cert.Certificate {
		certPEMBlocks = append(certPEMBlocks, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c}))
	}
	certPEM := bytes.Join(certPEMBlocks, nil)

	// Encode the private key to PEM, which means we first need to convert to PKCS8 (DER).
	privateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key into PKCS8: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPKCS8})

	return certPEM, keyPEM, nil
}

// randomSerial generates a random 128-bit serial number.
func randomSerial(rng io.Reader) (*big.Int, error) {
	return rand.Int(rng, new(big.Int).Lsh(big.NewInt(1), 128))
}
