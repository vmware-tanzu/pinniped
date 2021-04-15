// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package execcredcache implements a cache for Kubernetes ExecCredential data.
package execcredcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

const (
	// defaultFileLockTimeout is how long we will wait trying to acquire the file lock on the cache file before timing out.
	defaultFileLockTimeout = 10 * time.Second

	// defaultFileLockRetryInterval is how often we will poll while waiting for the file lock to become available.
	defaultFileLockRetryInterval = 10 * time.Millisecond
)

type Cache struct {
	path        string
	errReporter func(error)
	trylockFunc func() error
	unlockFunc  func() error
}

func New(path string) *Cache {
	lock := flock.New(path + ".lock")
	return &Cache{
		path: path,
		trylockFunc: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), defaultFileLockTimeout)
			defer cancel()
			_, err := lock.TryLockContext(ctx, defaultFileLockRetryInterval)
			return err
		},
		unlockFunc:  lock.Unlock,
		errReporter: func(_ error) {},
	}
}

func (c *Cache) Get(key interface{}) *clientauthenticationv1beta1.ExecCredential {
	// If the cache file does not exist, exit immediately with no error log
	if _, err := os.Stat(c.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Read the cache and lookup the matching entry. If one exists, update its last used timestamp and return it.
	var result *clientauthenticationv1beta1.ExecCredential
	cacheKey := jsonSHA256Hex(key)
	c.withCache(func(cache *credCache) {
		// Find the existing entry, if one exists
		for i := range cache.Entries {
			if cache.Entries[i].Key == cacheKey {
				result = &clientauthenticationv1beta1.ExecCredential{
					TypeMeta: metav1.TypeMeta{
						Kind:       "ExecCredential",
						APIVersion: "client.authentication.k8s.io/v1beta1",
					},
					Status: cache.Entries[i].Credential,
				}

				// Update the last-used timestamp.
				cache.Entries[i].LastUsedTimestamp = metav1.Now()
				break
			}
		}
	})
	return result
}

func (c *Cache) Put(key interface{}, cred *clientauthenticationv1beta1.ExecCredential) {
	// Create the cache directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		c.errReporter(fmt.Errorf("could not create credential cache directory: %w", err))
		return
	}

	// Mutate the cache to upsert the new entry.
	cacheKey := jsonSHA256Hex(key)
	c.withCache(func(cache *credCache) {
		// Find the existing entry, if one exists
		for i := range cache.Entries {
			if cache.Entries[i].Key == cacheKey {
				// Update the stored entry and return.
				cache.Entries[i].Credential = cred.Status
				cache.Entries[i].LastUsedTimestamp = metav1.Now()
				return
			}
		}

		// If there's not an entry for this key, insert one.
		now := metav1.Now()
		cache.Entries = append(cache.Entries, entry{
			Key:               cacheKey,
			CreationTimestamp: now,
			LastUsedTimestamp: now,
			Credential:        cred.Status,
		})
	})
}

func jsonSHA256Hex(key interface{}) string {
	hash := sha256.New()
	if err := json.NewEncoder(hash).Encode(key); err != nil {
		panic(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// withCache is an internal helper which locks, reads the cache, processes/mutates it with the provided function, then
// saves it back to the file.
func (c *Cache) withCache(transact func(*credCache)) {
	// Grab the file lock so we have exclusive access to read the file.
	if err := c.trylockFunc(); err != nil {
		c.errReporter(fmt.Errorf("could not lock cache file: %w", err))
		return
	}

	// Unlock the file at the end of this call, bubbling up the error if things were otherwise successful.
	defer func() {
		if err := c.unlockFunc(); err != nil {
			c.errReporter(fmt.Errorf("could not unlock cache file: %w", err))
		}
	}()

	// Try to read the existing cache.
	cache, err := readCache(c.path)
	if err != nil {
		// If that fails, fall back to resetting to a blank slate.
		c.errReporter(fmt.Errorf("failed to read cache, resetting: %w", err))
		cache = emptyCache()
	}

	// Normalize the cache before modifying it, to remove any entries that have already expired.
	cache = cache.normalized()

	// Process/mutate the cache using the provided function.
	transact(cache)

	// Normalize again to put everything into a known order.
	cache = cache.normalized()

	// Marshal the cache back to YAML and save it to the file.
	if err := cache.writeTo(c.path); err != nil {
		c.errReporter(fmt.Errorf("could not write cache: %w", err))
	}
}
