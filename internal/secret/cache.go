// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"sync"
	"sync/atomic"
)

type Cache struct {
	csrfCookieEncoderHashKey atomic.Value
	federationDomainCacheMap sync.Map
}

// New returns an empty Cache.
func New() *Cache { return &Cache{} }

type federationDomainCache struct {
	tokenHMACKey         atomic.Value
	stateEncoderHashKey  atomic.Value
	stateEncoderBlockKey atomic.Value
}

func (c *Cache) GetCSRFCookieEncoderHashKey() []byte {
	return bytesOrNil(c.csrfCookieEncoderHashKey.Load())
}

func (c *Cache) SetCSRFCookieEncoderHashKey(key []byte) {
	c.csrfCookieEncoderHashKey.Store(key)
}

func (c *Cache) GetTokenHMACKey(oidcIssuer string) []byte {
	return bytesOrNil(c.getFederationDomainCache(oidcIssuer).tokenHMACKey.Load())
}

func (c *Cache) SetTokenHMACKey(oidcIssuer string, key []byte) {
	c.getFederationDomainCache(oidcIssuer).tokenHMACKey.Store(key)
}

func (c *Cache) GetStateEncoderHashKey(oidcIssuer string) []byte {
	return bytesOrNil(c.getFederationDomainCache(oidcIssuer).stateEncoderHashKey.Load())
}

func (c *Cache) SetStateEncoderHashKey(oidcIssuer string, key []byte) {
	c.getFederationDomainCache(oidcIssuer).stateEncoderHashKey.Store(key)
}

func (c *Cache) GetStateEncoderBlockKey(oidcIssuer string) []byte {
	return bytesOrNil(c.getFederationDomainCache(oidcIssuer).stateEncoderBlockKey.Load())
}

func (c *Cache) SetStateEncoderBlockKey(oidcIssuer string, key []byte) {
	c.getFederationDomainCache(oidcIssuer).stateEncoderBlockKey.Store(key)
}

func (c *Cache) getFederationDomainCache(oidcIssuer string) *federationDomainCache {
	value, ok := c.federationDomainCacheMap.Load(oidcIssuer)
	if !ok {
		value = &federationDomainCache{}
		c.federationDomainCacheMap.Store(oidcIssuer, value)
	}
	return value.(*federationDomainCache)
}

func bytesOrNil(b interface{}) []byte {
	if b == nil {
		return nil
	}
	return b.([]byte)
}
