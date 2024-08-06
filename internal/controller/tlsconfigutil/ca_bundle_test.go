// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsconfigutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/certauthority"
)

func TestNewCABundleHash(t *testing.T) {
	sha256OfNil := CABundleHash{hash: [32]byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}}

	// On the command line, `echo "test" | shasum -a 256` yields "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	// which is 32 bytes of data encoded as 64 characters.
	// https://stackoverflow.com/a/70565837
	// This is the actual binary data:
	sha256OfTest := CABundleHash{hash: [32]byte{159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8}}

	t.Run("will hash the data given", func(t *testing.T) {
		caBundleHash := NewCABundleHash([]byte("test"))

		require.True(t, sha256OfTest.Equal(caBundleHash))
		require.Equal(t, sha256OfTest, caBundleHash)
	})

	t.Run("will return the hash of nil input", func(t *testing.T) {
		caBundleHash := NewCABundleHash(nil)

		require.True(t, sha256OfNil.Equal(caBundleHash))
		require.Equal(t, sha256OfNil, caBundleHash)
	})

	t.Run("will return the hash of empty input", func(t *testing.T) {
		caBundleHash := NewCABundleHash([]byte{})

		require.True(t, sha256OfNil.Equal(caBundleHash))
		require.Equal(t, sha256OfNil, caBundleHash)
	})
}

func TestNewCABundle(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)

	t.Run("generates the certPool and hash for certificate input", func(t *testing.T) {
		caBundle, ok := NewCABundle(testCA.Bundle())
		require.True(t, ok)

		require.Equal(t, testCA.Bundle(), caBundle.PEMBytes())
		require.Equal(t, NewCABundleHash(testCA.Bundle()), caBundle.Hash())
		require.Equal(t, string(testCA.Bundle()), caBundle.PEMString())
		require.True(t, testCA.Pool().Equal(caBundle.CertPool()), "should be the cert pool of the testCA")
	})

	t.Run("returns false for non-certificate input", func(t *testing.T) {
		caBundle, ok := NewCABundle([]byte("here are some bytes"))
		require.False(t, ok)

		require.Equal(t, []byte("here are some bytes"), caBundle.PEMBytes())
		require.Equal(t, NewCABundleHash([]byte("here are some bytes")), caBundle.Hash())
		require.Equal(t, "here are some bytes", caBundle.PEMString())
		require.True(t, x509.NewCertPool().Equal(caBundle.CertPool()), "should be an empty cert pool")
	})
}

func TestPEMBytes(t *testing.T) {
	t.Run("returns the CA bundle", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("here are some bytes"))

		require.Equal(t, []byte("here are some bytes"), caBundle.PEMBytes())
	})

	t.Run("handles nil bundle by returning nil", func(t *testing.T) {
		caBundle, _ := NewCABundle(nil)
		require.Nil(t, caBundle.PEMBytes())
	})

	t.Run("handles empty bundle by returning empty byte array", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte{})
		require.Equal(t, []byte{}, caBundle.PEMBytes())
	})

	t.Run("handles nil receiver by returning nil", func(t *testing.T) {
		var nilCABundle *CABundle
		require.Nil(t, nilCABundle.PEMBytes())
	})
}

func TestPEMString(t *testing.T) {
	t.Run("returns the CA bundle PEM string", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("here is a string"))

		require.Equal(t, "here is a string", caBundle.PEMString())
	})

	t.Run("handles nil bundle by returning empty string", func(t *testing.T) {
		caBundle, _ := NewCABundle(nil)

		require.Equal(t, "", caBundle.PEMString())
	})

	t.Run("handles empty bundle by returning empty string", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte{})

		require.Equal(t, "", caBundle.PEMString())
	})

	t.Run("handles nil receiver by returning empty string", func(t *testing.T) {
		var nilCABundle *CABundle
		require.Empty(t, nilCABundle.PEMString())
	})
}

func TestCertPool(t *testing.T) {
	t.Run("returns the certPool when the caBundle is valid", func(t *testing.T) {
		testCA, err := certauthority.New("Test CA", 1*time.Hour)
		require.NoError(t, err)

		caBundle, _ := NewCABundle(testCA.Bundle())

		require.True(t, testCA.Pool().Equal(caBundle.CertPool()))
	})

	t.Run("returns a nil certPool when the caBundle is nil", func(t *testing.T) {
		caBundle, _ := NewCABundle(nil)

		require.Nil(t, caBundle.CertPool())
	})

	t.Run("returns a nil certPool when the caBundle is empty", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte{})

		require.Nil(t, caBundle.CertPool())
	})

	t.Run("handles nil receiver by returning nil", func(t *testing.T) {
		var nilCABundle *CABundle
		require.Nil(t, nilCABundle.CertPool())
	})
}

func TestHash(t *testing.T) {
	t.Run("returns the Hash of the given CA bundle", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte("this is a CA bundle"))

		require.True(t, NewCABundleHash([]byte("this is a CA bundle")).Equal(caBundle.Hash()))
	})

	t.Run("returns the Hash of nil when the CA bundle is nil", func(t *testing.T) {
		caBundle, _ := NewCABundle(nil)

		require.True(t, NewCABundleHash(nil).Equal(caBundle.Hash()))
	})

	t.Run("returns the Hash of nil when the CA bundle is empty", func(t *testing.T) {
		caBundle, _ := NewCABundle([]byte{})

		require.True(t, NewCABundleHash(nil).Equal(caBundle.Hash()))
	})

	t.Run("returns the Hash of nil when the receiver is nil", func(t *testing.T) {
		var nilCABundle *CABundle

		require.True(t, NewCABundleHash(nil).Equal(nilCABundle.Hash()))
	})
}
