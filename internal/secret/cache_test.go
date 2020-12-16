// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const (
	issuer      = "some-issuer"
	otherIssuer = "other-issuer"
)

var (
	csrfCookieEncoderHashKey = []byte("csrf-cookie-encoder-hash-key")
	tokenHMACKey             = []byte("token-hmac-key")
	stateEncoderHashKey      = []byte("state-encoder-hash-key")
	otherStateEncoderHashKey = []byte("other-state-encoder-hash-key")
	stateEncoderBlockKey     = []byte("state-encoder-block-key")
)

func TestCache(t *testing.T) {
	c := New()

	// Validate we get a nil return value when stuff does not exist.
	require.Nil(t, c.GetCSRFCookieEncoderHashKey())
	require.Nil(t, c.GetTokenHMACKey(issuer))
	require.Nil(t, c.GetStateEncoderHashKey(issuer))
	require.Nil(t, c.GetStateEncoderBlockKey(issuer))

	// Validate we get some nil and non-nil values when some stuff exists.
	c.SetCSRFCookieEncoderHashKey(csrfCookieEncoderHashKey)
	require.Equal(t, csrfCookieEncoderHashKey, c.GetCSRFCookieEncoderHashKey())
	require.Nil(t, c.GetTokenHMACKey(issuer))
	c.SetStateEncoderHashKey(issuer, stateEncoderHashKey)
	require.Equal(t, stateEncoderHashKey, c.GetStateEncoderHashKey(issuer))
	require.Nil(t, c.GetStateEncoderBlockKey(issuer))

	// Validate we get non-nil values when all stuff exists.
	c.SetCSRFCookieEncoderHashKey(csrfCookieEncoderHashKey)
	c.SetTokenHMACKey(issuer, tokenHMACKey)
	c.SetStateEncoderHashKey(issuer, otherStateEncoderHashKey)
	c.SetStateEncoderBlockKey(issuer, stateEncoderBlockKey)
	require.Equal(t, csrfCookieEncoderHashKey, c.GetCSRFCookieEncoderHashKey())
	require.Equal(t, tokenHMACKey, c.GetTokenHMACKey(issuer))
	require.Equal(t, otherStateEncoderHashKey, c.GetStateEncoderHashKey(issuer))
	require.Equal(t, stateEncoderBlockKey, c.GetStateEncoderBlockKey(issuer))

	// Validate that stuff is still nil for an unknown issuer.
	require.Nil(t, c.GetTokenHMACKey(otherIssuer))
	require.Nil(t, c.GetStateEncoderHashKey(otherIssuer))
	require.Nil(t, c.GetStateEncoderBlockKey(otherIssuer))
}

// TestCacheSynchronized should mimic the behavior of an FederationDomain: multiple goroutines
// read the same fields, sequentially, from the cache.
func TestCacheSynchronized(t *testing.T) {
	c := New()

	c.SetCSRFCookieEncoderHashKey(csrfCookieEncoderHashKey)
	c.SetTokenHMACKey(issuer, tokenHMACKey)
	c.SetStateEncoderHashKey(issuer, stateEncoderHashKey)
	c.SetStateEncoderBlockKey(issuer, stateEncoderBlockKey)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	eg, _ := errgroup.WithContext(ctx)

	eg.Go(func() error {
		for i := 0; i < 100; i++ {
			require.Equal(t, csrfCookieEncoderHashKey, c.GetCSRFCookieEncoderHashKey())
			require.Equal(t, tokenHMACKey, c.GetTokenHMACKey(issuer))
			require.Equal(t, stateEncoderHashKey, c.GetStateEncoderHashKey(issuer))
			require.Equal(t, stateEncoderBlockKey, c.GetStateEncoderBlockKey(issuer))
		}
		return nil
	})

	eg.Go(func() error {
		for i := 0; i < 100; i++ {
			require.Equal(t, csrfCookieEncoderHashKey, c.GetCSRFCookieEncoderHashKey())
			require.Equal(t, tokenHMACKey, c.GetTokenHMACKey(issuer))
			require.Equal(t, stateEncoderHashKey, c.GetStateEncoderHashKey(issuer))
			require.Equal(t, stateEncoderBlockKey, c.GetStateEncoderBlockKey(issuer))
		}
		return nil
	})

	eg.Go(func() error {
		for i := 0; i < 100; i++ {
			require.Nil(t, c.GetTokenHMACKey(otherIssuer))
			require.Nil(t, c.GetStateEncoderHashKey(otherIssuer))
			require.Nil(t, c.GetStateEncoderBlockKey(otherIssuer))
		}
		return nil
	})

	require.NoError(t, eg.Wait())
}
