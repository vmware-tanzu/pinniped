// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"crypto/sha256"
	"crypto/x509"
)

type CABundleHash struct {
	hash [32]byte
}

func NewCABundleHash(bundle []byte) CABundleHash {
	return CABundleHash{
		hash: sha256.Sum256(bundle),
	}
}

func (a CABundleHash) Equal(b CABundleHash) bool {
	return a == b
}

// CABundle abstracts the internal representation of CA certificate bundles.
type CABundle struct {
	caBundle []byte
	sha256   CABundleHash
	certPool *x509.CertPool
}

func NewCABundle(caBundle []byte) (*CABundle, bool) {
	var certPool *x509.CertPool
	ok := true

	if len(caBundle) > 0 {
		certPool = x509.NewCertPool()
		ok = certPool.AppendCertsFromPEM(caBundle)
	}

	return &CABundle{
		caBundle: caBundle,
		sha256:   NewCABundleHash(caBundle),
		certPool: certPool,
	}, ok
}

// PEMBytes returns the CA certificate bundle PEM bytes.
func (c *CABundle) PEMBytes() []byte {
	if c == nil {
		return nil
	}
	return c.caBundle
}

// PEMString returns the certificate bundle PEM formatted as a string.
func (c *CABundle) PEMString() string {
	if c == nil {
		return ""
	}
	return string(c.caBundle)
}

// CertPool returns a X509 cert pool with the CA certificate bundle.
func (c *CABundle) CertPool() *x509.CertPool {
	if c == nil {
		return nil
	}
	return c.certPool
}

// Hash returns a sha256 sum of the CA bundle bytes.
func (c *CABundle) Hash() CABundleHash {
	if c == nil {
		return NewCABundleHash(nil)
	}
	return c.sha256
}
