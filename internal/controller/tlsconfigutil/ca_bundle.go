package tlsconfigutil

import (
	"crypto/sha256"
	"crypto/x509"
)

var sHA256OfEmptyData = sha256.Sum256(nil)
var zeroSHA256 = [32]byte{}

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
	if c == nil {
		return nil
	}
	return c.caBundle
}

// GetCABundlePemString returns the certificate bundle PEM formatted as a string.
func (c *CABundle) GetCABundlePemString() string {
	if c == nil {
		return ""
	}
	return string(c.caBundle)
}

// GetCertPool returns a X509 cert pool with the CA certificate bundle.
func (c *CABundle) GetCertPool() *x509.CertPool {
	if c == nil {
		return nil
	}
	return c.certPool
}

// GetCABundleHash returns a sha256 sum of the CA bundle bytes.
func (c *CABundle) GetCABundleHash() [32]byte {
	if c == nil || len(c.caBundle) < 1 {
		return sHA256OfEmptyData
	}
	// This handles improperly initialized receivers
	if c.sha256 == zeroSHA256 {
		c.sha256 = sha256.Sum256(c.caBundle)
	}
	return c.sha256 // note that this will always return the same hash for nil input
}

// IsEqual returns whether a CABundle has the same CA certificate bundle as another.
func (c *CABundle) IsEqual(other *CABundle) bool {
	return c.GetCABundleHash() == other.GetCABundleHash()
}
