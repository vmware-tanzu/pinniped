// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package dynamiccertauthority implements a x509 certificate authority capable of issuing
// certificates from a dynamically updating CA keypair.
package dynamiccertauthority

import (
	"crypto/x509/pkix"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"go.pinniped.dev/internal/certauthority"
)

// CA is a type capable of issuing certificates.
type CA struct {
	provider dynamiccertificates.CertKeyContentProvider
}

// New creates a new CA, ready to issue certs whenever the provided provider has a keypair to
// provide.
func New(provider dynamiccertificates.CertKeyContentProvider) *CA {
	return &CA{
		provider: provider,
	}
}

// IssuePEM issues a new server certificate for the given identity and duration, returning it as a
// pair of PEM-formatted byte slices for the certificate and private key.
func (c *CA) IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error) {
	caCrtPEM, caKeyPEM := c.provider.CurrentCertKeyContent()
	ca, err := certauthority.Load(string(caCrtPEM), string(caKeyPEM))
	if err != nil {
		return nil, nil, err
	}

	return ca.IssuePEM(subject, dnsNames, ttl)
}
