// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"time"

	"k8s.io/apimachinery/pkg/util/cache"
)

const tokenCacheKey = "token"

type ExpiringSingletonTokenCacheGet interface {
	Get() string
}

type ExpiringSingletonTokenCache interface {
	ExpiringSingletonTokenCacheGet
	Set(token string, ttl time.Duration)
}

type expiringCacheImpl struct {
	cache *cache.Expiring
}

var _ ExpiringSingletonTokenCacheGet = &expiringCacheImpl{}
var _ ExpiringSingletonTokenCache = &expiringCacheImpl{}

func NewExpiringSingletonTokenCache() ExpiringSingletonTokenCache {
	return &expiringCacheImpl{cache: cache.NewExpiring()}
}

func (e *expiringCacheImpl) Get() string {
	maybeToken, ok := e.cache.Get(tokenCacheKey)
	if !ok {
		return ""
	}

	token, ok := maybeToken.(string)
	if !ok {
		return ""
	}

	return token
}

func (e *expiringCacheImpl) Set(token string, ttl time.Duration) {
	e.cache.Set(tokenCacheKey, token, ttl)
}
