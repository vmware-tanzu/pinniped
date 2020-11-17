// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"testing"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/require"
)

func TestPKCE(t *testing.T) {
	p, err := Generate()
	require.NoError(t, err)

	cfg := oauth2.Config{}
	authCodeURL, err := url.Parse(cfg.AuthCodeURL("", p.Challenge(), p.Method()))
	require.NoError(t, err)

	// The code_challenge must be 256 bits (sha256) encoded as unpadded urlsafe base64.
	chal, err := base64.RawURLEncoding.DecodeString(authCodeURL.Query().Get("code_challenge"))
	require.NoError(t, err)
	require.Len(t, chal, 32)

	// The code_challenge_method must be a fixed value.
	require.Equal(t, "S256", authCodeURL.Query().Get("code_challenge_method"))

	// The code_verifier param should be 64 hex characters.
	verifyURL, err := url.Parse(cfg.AuthCodeURL("", p.Verifier()))
	require.NoError(t, err)
	require.Regexp(t, `\A[0-9a-f]{64}\z`, verifyURL.Query().Get("code_verifier"))

	var empty bytes.Buffer
	p, err = generate(&empty)
	require.EqualError(t, err, "could not generate PKCE code: EOF")
	require.Empty(t, p)
}
