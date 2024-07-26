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

func NewCABundle(caBundle []byte) (*CABundle, bool) {
	var certPool *x509.CertPool
	ok := true

	if len(caBundle) > 0 {
		certPool = x509.NewCertPool()
		ok = certPool.AppendCertsFromPEM(caBundle)
	}

	return &CABundle{
		caBundle: caBundle,
		sha256:   sha256.Sum256(caBundle),
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
func (c *CABundle) Hash() [32]byte {
	if c == nil || len(c.caBundle) < 1 {
		return sHA256OfEmptyData
	}
	// This handles improperly initialized receivers
	if c.sha256 == zeroSHA256 {
		c.sha256 = sha256.Sum256(c.caBundle)
	}
	return c.sha256 // note that this will always return the same hash for nil input
}
