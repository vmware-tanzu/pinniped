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

// KeyFunc returns a single key: a symmetric key.
type KeyFunc func() []byte

// Codec can dynamically encode and decode information by using a KeyFunc to get its keys
// just-in-time.
type Codec struct {
	signingKeyFunc    KeyFunc
	encryptionKeyFunc KeyFunc
}

// New creates a new Codec that will use the provided keyFuncs for its key source.
func New(signingKeyFunc, encryptionKeyFunc KeyFunc) *Codec {
	return &Codec{
		signingKeyFunc:    signingKeyFunc,
		encryptionKeyFunc: encryptionKeyFunc,
	}
}

// Encode implements oidc.Encode().
func (c *Codec) Encode(name string, value interface{}) (string, error) {
	return securecookie.New(c.signingKeyFunc(), c.encryptionKeyFunc()).Encode(name, value)
}

// Decode implements oidc.Decode().
func (c *Codec) Decode(name string, value string, into interface{}) error {
	return securecookie.New(c.signingKeyFunc(), c.encryptionKeyFunc()).Decode(name, value, into)
}
