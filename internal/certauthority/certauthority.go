/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

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
	"time"
)

// CA holds the state for a simple x509 certificate authority suitable for use in an aggregated API service.
type CA struct {
	// secure random number generators for various steps (usually crypto/rand.Reader, but broken out here for tests).
	serialRNG  io.Reader
	keygenRNG  io.Reader
	signingRNG io.Reader

	// clock tells the current time (usually time.Now(), but broken out here for tests).
	clock func() time.Time

	// signer is the private key for the current CA.
	signer crypto.Signer

	// caCert is the DER-encoded certificate for the current CA.
	caCertBytes []byte
}

// Option to pass when calling New.
type Option func(*CA) error

func New(subject pkix.Name, opts ...Option) (*CA, error) {
	// Initialize the result by starting with some defaults and applying any provided options.
	ca := CA{
		serialRNG:  rand.Reader,
		keygenRNG:  rand.Reader,
		signingRNG: rand.Reader,
		clock:      time.Now,
	}
	for _, opt := range opts {
		if err := opt(&ca); err != nil {
			return nil, err
		}
	}

	// Generate a random serial for the CA
	serialNumber, err := randomSerial(ca.serialRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate CA serial: %w", err)
	}

	// Generate a new P256 keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), ca.keygenRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate CA private key: %w", err)
	}
	ca.signer = privateKey

	// Make a CA certificate valid for 100 years and backdated by one minute.
	now := ca.clock()
	notBefore := now.Add(-1 * time.Minute)
	notAfter := now.Add(24 * time.Hour * 365 * 100)

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
	caCertBytes, err := x509.CreateCertificate(ca.signingRNG, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not issue CA certificate: %w", err)
	}
	ca.caCertBytes = caCertBytes
	return &ca, nil
}

// WriteBundle writes the current CA signing bundle in concatenated PEM format.
func (c *CA) WriteBundle(out io.Writer) error {
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: c.caCertBytes}); err != nil {
		return fmt.Errorf("could not encode CA certificate to PEM: %w", err)
	}
	return nil
}

// Bundle returns the current CA signing bundle in concatenated PEM format.
func (c *CA) Bundle() ([]byte, error) {
	var out bytes.Buffer
	err := c.WriteBundle(&out)
	return out.Bytes(), err
}

// Issue a new server certificate for the given identity and duration.
func (c *CA) Issue(subject pkix.Name, dnsNames []string, ttl time.Duration) (*tls.Certificate, error) {
	// Choose a random 128 bit serial number.
	serialNumber, err := randomSerial(c.serialRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate serial number for certificate: %w", err)
	}

	// Generate a new P256 keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), c.keygenRNG)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	// Make a CA caCert valid for the requested TTL and backdated by one minute.
	now := c.clock()
	notBefore := now.Add(-1 * time.Minute)
	notAfter := now.Add(ttl)

	// Parse the DER encoded certificate to get an x509.Certificate.
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("could not sign certificate: %w", err)
	}

	// Parse the DER encoded certificate back out into an *x509.Certificate.
	newCert, err := x509.ParseCertificate(certBytes)
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

// randomSerial generates a random 128 bit serial number.
func randomSerial(rng io.Reader) (*big.Int, error) {
	return rand.Int(rng, new(big.Int).Lsh(big.NewInt(1), 128))
}
