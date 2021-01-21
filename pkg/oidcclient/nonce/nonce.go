// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package nonce implements
package nonce

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Generate generates a new random OIDC nonce parameter of an appropriate size.
func Generate() (Nonce, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (Nonce, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate random nonce: %w", err)
	}
	return Nonce(hex.EncodeToString(buf[:])), nil
}

// Nonce implements some utilities for working with OIDC nonce parameters.
type Nonce string

// String returns the string encoding of this state value.
func (n *Nonce) String() string {
	return string(*n)
}

// Param returns the OAuth2 auth code parameter for sending the nonce during the authorization request.
func (n *Nonce) Param() oauth2.AuthCodeOption {
	return oidc.Nonce(string(*n))
}

// Validate the returned ID token). Returns true iff the nonce matches or the returned JWT does not have a nonce.
func (n *Nonce) Validate(token *oidc.IDToken) error {
	if subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(*n)) != 1 {
		return InvalidNonceError{Expected: *n, Got: Nonce(token.Nonce)}
	}
	return nil
}

// InvalidNonceError is returned by Validate when the observed nonce is invalid.
type InvalidNonceError struct {
	Expected Nonce
	Got      Nonce
}

func (e InvalidNonceError) Error() string {
	return fmt.Sprintf("invalid nonce (expected %q, got %q)", e.Expected.String(), e.Got.String())
}
