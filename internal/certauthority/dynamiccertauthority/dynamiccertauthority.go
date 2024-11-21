// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package dynamiccertauthority implements a x509 certificate authority capable of issuing
// certificates from a dynamically updating CA keypair.
package dynamiccertauthority

import (
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"go.pinniped.dev/internal/cert"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/clientcertissuer"
)

// ca is a type capable of issuing certificates.
type ca struct {
	provider dynamiccertificates.CertKeyContentProvider
}

// New creates a ClientCertIssuer, ready to issue certs whenever
// the given CertKeyContentProvider has a keypair to provide.
func New(provider dynamiccertificates.CertKeyContentProvider) clientcertissuer.ClientCertIssuer {
	return &ca{
		provider: provider,
	}
}

func (c *ca) Name() string {
	return c.provider.Name()
}

// IssueClientCertPEM issues a new client certificate for the given identity and duration, returning it as a
// pair of PEM-formatted byte slices for the certificate and private key, along with the notBefore and notAfter values.
func (c *ca) IssueClientCertPEM(username string, groups []string, ttl time.Duration) (*cert.PEM, error) {
	caCrtPEM, caKeyPEM := c.provider.CurrentCertKeyContent()
	// in the future we could split dynamiccert.Private into two interfaces (Private and PrivateRead)
	// and have this code take PrivateRead as input.  We would then add ourselves as a listener to
	// the PrivateRead.  This would allow us to only reload the CA contents when they actually change.
	ca, err := certauthority.Load(string(caCrtPEM), string(caKeyPEM))
	if err != nil {
		return nil, err
	}

	return ca.IssueClientCertPEM(username, groups, ttl)
}
