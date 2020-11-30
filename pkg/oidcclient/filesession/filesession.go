// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package filesession implements a simple YAML file-based login.sessionCache.
package filesession

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

const (
	// defaultFileLockTimeout is how long we will wait trying to acquire the file lock on the session file before timing out.
	defaultFileLockTimeout = 10 * time.Second

	// defaultFileLockRetryInterval is how often we will poll while waiting for the file lock to become available.
	defaultFileLockRetryInterval = 10 * time.Millisecond
)

// Option configures a cache in New().
type Option func(*Cache)

// WithErrorReporter is an Option that specifies a callback which will be invoked for each error reported during
// session cache operations. By default, these errors are silently ignored.
func WithErrorReporter(reporter func(error)) Option {
	return func(c *Cache) {
		c.errReporter = reporter
	}
}

// New returns a login.SessionCache implementation backed by the specified file path.
func New(path string, options ...Option) *Cache {
	lock := flock.New(path + ".lock")
	c := Cache{
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
	for _, opt := range options {
		opt(&c)
	}
	return &c
}

type Cache struct {
	path        string
	errReporter func(error)
	trylockFunc func() error
	unlockFunc  func() error
}

// GetToken looks up the cached data for the given parameters. It may return nil if no valid matching session is cached.
func (c *Cache) GetToken(key oidcclient.SessionCacheKey) *oidctypes.Token {
	// If the cache file does not exist, exit immediately with no error log
	if _, err := os.Stat(c.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Read the cache and lookup the matching entry. If one exists, update its last used timestamp and return it.
	var result *oidctypes.Token
	c.withCache(func(cache *sessionCache) {
		if entry := cache.lookup(key); entry != nil {
			result = &entry.Tokens
			entry.LastUsedTimestamp = metav1.Now()
		}
	})
	return result
}

// PutToken stores the provided token into the session cache under the given parameters. It does not return an error
// but may silently fail to update the session cache.
func (c *Cache) PutToken(key oidcclient.SessionCacheKey, token *oidctypes.Token) {
	// Create the cache directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		c.errReporter(fmt.Errorf("could not create session cache directory: %w", err))
		return
	}

	// Mutate the cache to upsert the new session entry.
	c.withCache(func(cache *sessionCache) {
		// Find the existing entry, if one exists
		if match := cache.lookup(key); match != nil {
			// Update the stored token.
			match.Tokens = *token
			match.LastUsedTimestamp = metav1.Now()
			return
		}

		// If there's not an entry for this key, insert one.
		now := metav1.Now()
		cache.insert(sessionEntry{
			Key:               key,
			CreationTimestamp: now,
			LastUsedTimestamp: now,
			Tokens:            *token,
		})
	})
}

// withCache is an internal helper which locks, reads the cache, processes/mutates it with the provided function, then
// saves it back to the file.
func (c *Cache) withCache(transact func(*sessionCache)) {
	// Grab the file lock so we have exclusive access to read the file.
	if err := c.trylockFunc(); err != nil {
		c.errReporter(fmt.Errorf("could not lock session file: %w", err))
		return
	}

	// Unlock the file at the end of this call, bubbling up the error if things were otherwise successful.
	defer func() {
		if err := c.unlockFunc(); err != nil {
			c.errReporter(fmt.Errorf("could not unlock session file: %w", err))
		}
	}()

	// Try to read the existing cache.
	cache, err := readSessionCache(c.path)
	if err != nil {
		// If that fails, fall back to resetting to a blank slate.
		c.errReporter(fmt.Errorf("failed to read cache, resetting: %w", err))
		cache = emptySessionCache()
	}

	// Process/mutate the session using the provided function.
	transact(cache)

	// Marshal the session back to YAML and save it to the file.
	if err := cache.writeTo(c.path); err != nil {
		c.errReporter(fmt.Errorf("could not write session cache: %w", err))
	}
}
