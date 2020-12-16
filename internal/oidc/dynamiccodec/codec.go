// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package dynamiccodec provides a type that can encode information using a just-in-time signing and
// (optionally) encryption secret.
package dynamiccodec

import (
	"time"

	"github.com/gorilla/securecookie"

	"go.pinniped.dev/internal/oidc"
)

var _ oidc.Codec = &Codec{}

// KeyFunc returns a single key: a symmetric key.
type KeyFunc func() []byte

// Codec can dynamically encode and decode information by using a KeyFunc to get its keys
// just-in-time.
type Codec struct {
	lifespan          time.Duration
	signingKeyFunc    KeyFunc
	encryptionKeyFunc KeyFunc
}

// New creates a new Codec that will use the provided keyFuncs for its key source, and
// use the securecookie.JSONEncoder. The securecookie.JSONEncoder is used because the default
// securecookie.GobEncoder is less compact and more difficult to make forward compatible.
//
// The returned Codec will make ensure that the encoded values will only be valid for the provided
// lifespan.
func New(lifespan time.Duration, signingKeyFunc, encryptionKeyFunc KeyFunc) *Codec {
	return &Codec{
		lifespan:          lifespan,
		signingKeyFunc:    signingKeyFunc,
		encryptionKeyFunc: encryptionKeyFunc,
	}
}

// Encode implements oidc.Encode().
func (c *Codec) Encode(name string, value interface{}) (string, error) {
	return c.delegate().Encode(name, value)
}

// Decode implements oidc.Decode().
func (c *Codec) Decode(name string, value string, into interface{}) error {
	return c.delegate().Decode(name, value, into)
}

func (c *Codec) delegate() *securecookie.SecureCookie {
	codec := securecookie.New(c.signingKeyFunc(), c.encryptionKeyFunc())
	codec.MaxAge(int(c.lifespan.Seconds()))
	codec.SetSerializer(securecookie.JSONEncoder{})
	return codec
}
