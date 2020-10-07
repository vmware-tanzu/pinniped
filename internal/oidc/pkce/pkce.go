// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// Generate generates a new random PKCE code.
func Generate() (Code, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (Code, error) {
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", errors.WithMessage(err, "could not generate PKCE code")
	}
	return Code(hex.EncodeToString(buf[:])), nil
}

// Code implements the basic options required for RFC 7636: Proof Key for Code Exchange (PKCE).
type Code string

// Challenge returns the OAuth2 auth code parameter for sending the PKCE code challenge.
func (p *Code) Challenge() oauth2.AuthCodeOption {
	b := sha256.Sum256([]byte(*p))
	return oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(b[:]))
}

// Method returns the OAuth2 auth code parameter for sending the PKCE code challenge method.
func (p *Code) Method() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", "S256")
}

// Verifier returns the OAuth2 auth code parameter for sending the PKCE code verifier.
func (p *Code) Verifier() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", string(*p))
}
