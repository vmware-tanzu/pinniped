// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idpcache implements a cache of active identity providers.
package idpcache

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"go.pinniped.dev/internal/controllerlib"
)

var (
	// ErrNoIDPs is returned by Cache.AuthenticateToken() when there are no IDPs configured.
	ErrNoIDPs = fmt.Errorf("no identity providers are loaded")

	// ErrIndeterminateIDP is returned by Cache.AuthenticateToken() when the correct IDP cannot be determined.
	ErrIndeterminateIDP = fmt.Errorf("could not uniquely match against an identity provider")
)

// Cache implements the authenticator.Token interface by multiplexing across a dynamic set of identity providers
// loaded from IDP resources.
type Cache struct {
	cache sync.Map
}

// New returns an empty cache.
func New() *Cache {
	return &Cache{}
}

// Store an identity provider into the cache.
func (c *Cache) Store(key controllerlib.Key, value authenticator.Token) {
	c.cache.Store(key, value)
}

// Delete an identity provider from the cache.
func (c *Cache) Delete(key controllerlib.Key) {
	c.cache.Delete(key)
}

// Keys currently stored in the cache.
func (c *Cache) Keys() []controllerlib.Key {
	var result []controllerlib.Key
	c.cache.Range(func(key, _ interface{}) bool {
		result = append(result, key.(controllerlib.Key))
		return true
	})
	return result
}

// AuthenticateToken validates the provided token against the currently loaded identity providers.
func (c *Cache) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	var matchingIDPs []authenticator.Token
	c.cache.Range(func(key, value interface{}) bool {
		matchingIDPs = append(matchingIDPs, value.(authenticator.Token))
		return true
	})

	// Return an error if there are no known IDPs.
	if len(matchingIDPs) == 0 {
		return nil, false, ErrNoIDPs
	}

	// For now, allow there to be only exactly one IDP (until we specify a good mechanism for selecting one).
	if len(matchingIDPs) != 1 {
		return nil, false, ErrIndeterminateIDP
	}

	return matchingIDPs[0].AuthenticateToken(ctx, token)
}
