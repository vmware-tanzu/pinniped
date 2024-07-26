package tlsconfigutil

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/certauthority"
)

func TestNewCABundle(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)

	t.Run("generates the certPool and hash for certificate input", func(t *testing.T) {
		caBundle, ok := NewCABundle(testCA.Bundle())
		require.True(t, ok)

		require.Equal(t, testCA.Bundle(), caBundle.GetCABundle())
		require.Equal(t, sha256.Sum256(testCA.Bundle()), caBundle.GetCABundleHash())
		require.Equal(t, string(testCA.Bundle()), caBundle.GetCABundlePemString())
		require.True(t, testCA.Pool().Equal(caBundle.GetCertPool()), "should be the cert pool of the testCA")
	})

	t.Run("returns false for non-certificate input", func(t *testing.T) {
		caBundle, ok := NewCABundle([]byte("here are some bytes"))
		require.False(t, ok)

		require.Equal(t, []byte("here are some bytes"), caBundle.GetCABundle())
		require.Equal(t, sha256.Sum256([]byte("here are some bytes")), caBundle.GetCABundleHash())
		require.Equal(t, "here are some bytes", caBundle.GetCABundlePemString())
		require.True(t, x509.NewCertPool().Equal(caBundle.GetCertPool()), "should be an empty cert pool")
	})
}

func TestGetCABundle(t *testing.T) {
	t.Run("returns the CA bundle", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("here are some bytes"))

		require.Equal(t, []byte("here are some bytes"), caBundle.GetCABundle())
	})

	t.Run("handles nil receiver by returning nil", func(t *testing.T) {
		var nilCABundle *CABundle
		var expected []byte
		require.Equal(t, expected, nilCABundle.GetCABundle())
	})
}

func TestGetCABundlePemString(t *testing.T) {
	t.Run("returns the CA bundle PEM string", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("here is a string"))

		require.Equal(t, "here is a string", caBundle.GetCABundlePemString())
	})

	t.Run("handles nil receiver by returning empty sstring", func(t *testing.T) {
		var nilCABundle *CABundle
		require.Equal(t, "", nilCABundle.GetCABundlePemString())
	})
}

func TestGetCertPool(t *testing.T) {
	t.Run("returns the generated cert pool", func(t *testing.T) {
		caBundle, _ := NewCABundle(nil)

		require.Equal(t, x509.NewCertPool(), caBundle.GetCertPool())
	})

	t.Run("handles nil receiver by returning nil", func(t *testing.T) {
		var nilCABundle *CABundle
		var expected *x509.CertPool
		require.Equal(t, expected, nilCABundle.GetCertPool())
	})
}

func TestGetCABundleHash(t *testing.T) {
	sha256OfNil := [32]uint8{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}

	// On the command line, `echo "test" | shasum -a 256` yields "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	// which is 32 bytes of data encoded as 64 characters.
	// https://stackoverflow.com/a/70565837
	// This is the actual binary data:
	sha256OfTest := [32]byte{159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8}

	t.Run("returns the SHA256", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("test"))

		require.Equal(t, sha256OfTest, caBundle.GetCABundleHash())
	})

	t.Run("handles nil receiver by returning the hash of nil", func(t *testing.T) {
		var nilCABundle *CABundle

		require.Equal(t, sha256OfNil, nilCABundle.GetCABundleHash())
	})

	t.Run("handles improperly initialized receiver by returning the hash of nil", func(t *testing.T) {
		caBundle := &CABundle{}

		require.Equal(t, sha256OfNil, caBundle.GetCABundleHash())
	})

	t.Run("handles improperly initialized receiver by computing the hash", func(t *testing.T) {
		caBundle := &CABundle{
			caBundle: []byte("test"),
		}

		require.Equal(t, sha256OfTest, caBundle.GetCABundleHash())
	})
}

func TestCABundleIsEqual(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(testCA.Bundle()))

	tests := []struct {
		name     string
		left     *CABundle
		right    *CABundle
		expected bool
	}{
		{
			name:     "should return equal when left and right are nil",
			left:     nil,
			right:    nil,
			expected: true,
		},
		{
			name:     "should return equal when left is nil and right is empty",
			left:     nil,
			right:    &CABundle{},
			expected: true,
		},
		{
			name:     "should return equal when right is nil and left is empty",
			left:     &CABundle{},
			right:    nil,
			expected: true,
		},
		{
			name: "should return equal when both left and right have same CA certificate bytes",
			left: func() *CABundle {
				caBundle, _ := NewCABundle(testCA.Bundle())
				return caBundle
			}(),
			right: func() *CABundle {
				caBundle, _ := NewCABundle(testCA.Bundle())
				return caBundle
			}(),
			expected: true,
		},
		{
			name: "should return not equal when both left and right do not have same CA certificate bytes",
			left: func() *CABundle {
				caBundle, _ := NewCABundle(testCA.Bundle())
				return caBundle
			}(),
			right: func() *CABundle {
				caBundle, _ := NewCABundle([]byte("something that is not a cert"))
				return caBundle
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, tt.left.IsEqual(tt.right))
			require.Equal(t, tt.expected, tt.right.IsEqual(tt.left))
		})
	}
}
