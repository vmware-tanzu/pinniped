// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secret

type Cache struct {
	csrfCookieEncoderHashKey  []byte
	csrfCookieEncoderBlockKey []byte
	oidcProviderCacheMap      map[string]*OIDCProviderCache
}

func (c *Cache) GetCSRFCookieEncoderHashKey() []byte {
	return c.csrfCookieEncoderHashKey
}

func (c *Cache) SetCSRFCookieEncoderHashKey(key []byte) {
	c.csrfCookieEncoderHashKey = key
}

func (c *Cache) GetCSRFCookieEncoderBlockKey() []byte {
	return c.csrfCookieEncoderBlockKey
}

func (c *Cache) SetCSRFCookieEncoderBlockKey(key []byte) {
	c.csrfCookieEncoderBlockKey = key
}

func (c *Cache) GetOIDCProviderCacheFor(oidcIssuer string) *OIDCProviderCache {
	return c.oidcProviderCaches()[oidcIssuer]
}

func (c *Cache) SetOIDCProviderCacheFor(oidcIssuer string, oidcProviderCache *OIDCProviderCache) {
	c.oidcProviderCaches()[oidcIssuer] = oidcProviderCache
}

func (c *Cache) oidcProviderCaches() map[string]*OIDCProviderCache {
	if c.oidcProviderCacheMap == nil {
		c.oidcProviderCacheMap = map[string]*OIDCProviderCache{}
	}
	return c.oidcProviderCacheMap
}

type OIDCProviderCache struct {
	tokenHMACKey         []byte
	stateEncoderHashKey  []byte
	stateEncoderBlockKey []byte
}

func (o *OIDCProviderCache) GetTokenHMACKey() []byte {
	return o.tokenHMACKey
}

func (o *OIDCProviderCache) SetTokenHMACKey(key []byte) {
	o.tokenHMACKey = key
}

func (o *OIDCProviderCache) GetStateEncoderHashKey() []byte {
	return o.stateEncoderHashKey
}

func (o *OIDCProviderCache) SetStateEncoderHashKey(key []byte) {
	o.stateEncoderHashKey = key
}

func (o *OIDCProviderCache) GetStateEncoderBlockKey() []byte {
	return o.stateEncoderBlockKey
}

func (o *OIDCProviderCache) SetStateEncoderBlockKey(key []byte) {
	o.stateEncoderBlockKey = key
}
