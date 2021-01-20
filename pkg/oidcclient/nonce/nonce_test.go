// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nonce

import (
	"bytes"
	"errors"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNonce(t *testing.T) {
	n, err := Generate()
	require.NoError(t, err)
	require.Len(t, n, 32)
	require.Len(t, n.String(), 32)

	cfg := oauth2.Config{}
	authCodeURL, err := url.Parse(cfg.AuthCodeURL("", n.Param()))
	require.NoError(t, err)
	require.Equal(t, n.String(), authCodeURL.Query().Get("nonce"))

	require.Error(t, n.Validate(&oidc.IDToken{}))
	require.NoError(t, n.Validate(&oidc.IDToken{Nonce: string(n)}))

	err = n.Validate(&oidc.IDToken{Nonce: string(n) + "x"})
	require.Error(t, err)
	require.True(t, errors.As(err, &InvalidNonceError{}))
	require.Contains(t, err.Error(), string(n)+"x")

	var empty bytes.Buffer
	n, err = generate(&empty)
	require.EqualError(t, err, "could not generate random nonce: EOF")
	require.Empty(t, n)
}
