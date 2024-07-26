package tlsconfigutil

import (
	"crypto/sha256"
	"crypto/x509"
)

// CABundle abstracts the internal representation of CA certificate bundles.
type CABundle struct {
	caBundle []byte
	sha256   [32]byte
	certPool *x509.CertPool
}

func NewCABundle(caBundle []byte, certPool *x509.CertPool) *CABundle {
	return &CABundle{
		caBundle: caBundle,
		sha256:   sha256.Sum256(caBundle),
		certPool: certPool,
	}
}

// GetCABundle returns the CA certificate bundle PEM bytes.
func (c *CABundle) GetCABundle() []byte {
	return c.caBundle
}

// GetCABundlePemString returns the certificate bundle PEM formatted as a string.
func (c *CABundle) GetCABundlePemString() string {
	return string(c.caBundle)
}

// GetCertPool returns a X509 cert pool with the CA certificate bundle.
func (c *CABundle) GetCertPool() *x509.CertPool {
	return c.certPool
}

// GetCABundleHash returns a sha256 sum of the CA bundle bytes.
func (c *CABundle) GetCABundleHash() [32]byte {
	return sha256.Sum256(c.caBundle) // note that this will always return the same hash for nil input
}

// IsEqual returns whether a CABundle has the same CA certificate bundle as another.
func (c *CABundle) IsEqual(other *CABundle) bool {
	if c == nil && other == nil {
		return true
	}
	if c == nil || other == nil {
		return false
	}
	return sha256.Sum256(c.caBundle) == sha256.Sum256(other.GetCABundle())
}
