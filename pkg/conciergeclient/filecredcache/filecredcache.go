// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package filecredcache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/pkg/conciergeclient"
)

const (
	// defaultFileLockTimeout is how long we will wait trying to acquire the file lock on the credential cache file before timing out.
	defaultFileLockTimeout = 10 * time.Second

	// defaultFileLockRetryInterval is how often we will poll while waiting for the file lock to become available.
	defaultFileLockRetryInterval = 10 * time.Millisecond
)

// Option configures a cache in New().
type Option func(*Cache)

// WithErrorReporter is an Option that specifies a callback which will be invoked for each error reported during
// credential cache operations. By default, these errors are silently ignored.
func WithErrorReporter(reporter func(error)) Option {
	return func(c *Cache) {
		c.errReporter = reporter
	}
}

// New returns a conciergeclient.Cache implementation backed by the specified file path.
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

var _ conciergeclient.Cache = (*Cache)(nil)

// GetClusterCredential looks up the cached data for the given parameters. It may return nil if no valid matching credential is cached.
func (c *Cache) GetClusterCredential(key string) *clientauthenticationv1beta1.ExecCredentialStatus {
	// If the cache file does not exist, exit immediately with no error log
	if _, err := os.Stat(c.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Read the cache and lookup the matching entry. If one exists, update its last used timestamp and return it.
	var result *clientauthenticationv1beta1.ExecCredentialStatus
	c.withCache(func(cache *credCache) {
		if entry := cache.lookup(key); entry != nil {
			result = &entry.Credential
			entry.LastUsedTimestamp = metav1.Now()
		}
	})
	return result
}

// PutClusterCredential stores the provided credential into the cache under the given key. It does not return an error
// but may silently fail to update the session cache.
func (c *Cache) PutClusterCredential(key string, cred *clientauthenticationv1beta1.ExecCredentialStatus) {
	// Create the cache directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(c.path), 0700); err != nil && !errors.Is(err, os.ErrExist) {
		c.errReporter(fmt.Errorf("could not create credential cache directory: %w", err))
		return
	}

	// Mutate the cache to upsert the new session entry.
	c.withCache(func(cache *credCache) {
		// Find the existing entry, if one exists
		if match := cache.lookup(key); match != nil {
			// Update the stored token.
			match.Credential = *cred
			match.LastUsedTimestamp = metav1.Now()
			return
		}

		// If there's not an entry for this key, insert one.
		now := metav1.Now()
		cache.insert(credEntry{
			Key:               key,
			CreationTimestamp: now,
			LastUsedTimestamp: now,
			Credential:        *cred,
		})
	})
}

// withCache is an internal helper which locks, reads the cache, processes/mutates it with the provided function, then
// saves it back to the file.
func (c *Cache) withCache(transact func(cache *credCache)) {
	// Grab the file lock so we have exclusive access to read the file.
	if err := c.trylockFunc(); err != nil {
		c.errReporter(fmt.Errorf("could not lock credential cache file: %w", err))
		return
	}

	// Unlock the file at the end of this call, bubbling up the error if things were otherwise successful.
	defer func() {
		if err := c.unlockFunc(); err != nil {
			c.errReporter(fmt.Errorf("could not unlock credential cache file: %w", err))
		}
	}()

	// Try to read the existing cache.
	cache, err := readCredCache(c.path)
	if err != nil {
		// If that fails, fall back to resetting to a blank slate.
		c.errReporter(fmt.Errorf("failed to read cache, resetting: %w", err))
		cache = emptyCredCache()
	}

	// Process/mutate the cache using the provided function.
	transact(cache)

	// Marshal the cache back to YAML and save it to the file.
	if err := cache.writeTo(c.path); err != nil {
		c.errReporter(fmt.Errorf("could not write credential cache: %w", err))
	}
}
