// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8sCache "k8s.io/apimachinery/pkg/util/cache"
)

func TestExpiringSingletonTokenCache(t *testing.T) {
	cache := NewExpiringSingletonTokenCache()
	require.NotNil(t, cache)
	require.Empty(t, cache.Get())

	cache.Set("i am a 12 hour token", 12*time.Hour)
	require.Equal(t, "i am a 12 hour token", cache.Get())

	cache.Set("i am a 0-TTL token", time.Duration(0))
	time.Sleep(1 * time.Millisecond)
	require.Empty(t, cache.Get())

	cache.Set("i am a very short token", 1*time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	require.Empty(t, cache.Get())
}

func TestExpiringSingletonTokenCache_WithNonString(t *testing.T) {
	cache := &expiringCacheImpl{cache: k8sCache.NewExpiring()}
	cache.cache.Set(tokenCacheKey, true, 1*time.Hour)
	require.Empty(t, cache.Get())
}
