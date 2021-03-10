// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
)

// certBackdate is the amount of time before time.Now() that will be used to set
// a certificate's NotBefore field.
//
// This could certainly be made configurable by an installer of pinniped, but we
// will see if we can save adding a configuration knob with a reasonable default
// here.
const certBackdate = 10 * time.Second

type env struct {
	// secure random number generators for various steps (usually crypto/rand.Reader, but broken out here for tests).
	serialRNG  io.Reader
	keygenRNG  io.Reader
	signingRNG io.Reader

	// clock tells the current time (usually time.Now(), but broken out here for tests).
	clock func() time.Time

	// parse function to parse an ASN.1 byte slice into an x509 struct (normally x509.ParseCertificate)
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
var ErrInvalidCACertificate = fmt.Errorf("invalid CA certificate")

// Load a certificate authority from an existing certificate and private key (in PEM format).
func Load(certPEM string, keyPEM string) (*CA, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("could not load CA: %w", err)
	}
	if certCount := len(cert.Certificate); certCount != 1 {
		return nil, fmt.Errorf("%w: expected a single certificate, found %d certificates", ErrInvalidCACertificate, certCount)
	}
	return &CA{
		caCertBytes: cert.Certificate[0],
		signer:      cert.PrivateKey.(crypto.Signer),
		env:         secureEnv(),
	}, nil
}

// New generates a fresh certificate authority with the given subject and ttl.
func New(subject pkix.Name, ttl time.Duration) (*CA, error) {
	return newInternal(subject, ttl, secureEnv())
}

// newInternal is the internal guts of New, broken out for easier testing.
func newInternal(subject pkix.Name, ttl time.Duration, env env) (*CA, error) {
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
		Subject:               subject,
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

// Issue a new server certificate for the given identity and duration.
func (c *CA) Issue(subject pkix.Name, dnsNames []string, ips []net.IP, ttl time.Duration) (*tls.Certificate, error) {
	// Choose a random 128 bit serial number.
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

	// Parse the DER encoded certificate to get an x509.Certificate.
	caCert, err := x509.ParseCertificate(c.caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse CA certificate: %w", err)
	}

	// Sign a cert, getting back the DER-encoded certificate bytes.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// TODO split this function into two funcs that handle client and serving certs differently
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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

// IssuePEM issues a new server certificate for the given identity and duration, returning it as a pair of
// PEM-formatted byte slices for the certificate and private key.
func (c *CA) IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error) {
	return toPEM(c.Issue(subject, dnsNames, nil, ttl))
}

func toPEM(cert *tls.Certificate, err error) ([]byte, []byte, error) {
	// If the wrapped Issue() returned an error, pass it back.
	if err != nil {
		return nil, nil, err
	}

	certPEM, keyPEM, err := ToPEM(cert)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

// Encode a tls.Certificate into a private key PEM and a cert chain PEM.
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

// randomSerial generates a random 128 bit serial number.
func randomSerial(rng io.Reader) (*big.Int, error) {
	return rand.Int(rng, new(big.Int).Lsh(big.NewInt(1), 128))
}
