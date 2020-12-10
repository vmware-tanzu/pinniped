// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package dynamiccodec provides a type that can encode information using a just-in-time signing and
// (optionally) encryption secret.
package dynamiccodec

import (
	"github.com/gorilla/securecookie"

	"go.pinniped.dev/internal/oidc"
)

var _ oidc.Codec = &Codec{}

// KeyFunc returns 2 keys: a required signing key, and an optional encryption key.
type KeyFunc func() ([]byte, []byte)

// Codec can dynamically encode and decode information by using a KeyFunc to get its keys
// just-in-time.
type Codec struct {
	keyFunc KeyFunc
}

// New creates a new Codec that will use the provided keyFunc for its key source.
func New(keyFunc KeyFunc) *Codec {
	return &Codec{
		keyFunc: keyFunc,
	}
}

// Encode implements oidc.Encode().
func (c *Codec) Encode(name string, value interface{}) (string, error) {
	signingKey, encryptionKey := c.keyFunc()
	return securecookie.New(signingKey, encryptionKey).Encode(name, value)
}

// Decode implements oidc.Decode().
func (c *Codec) Decode(name string, value string, into interface{}) error {
	signingKey, encryptionKey := c.keyFunc()
	return securecookie.New(signingKey, encryptionKey).Decode(name, value, into)
}
