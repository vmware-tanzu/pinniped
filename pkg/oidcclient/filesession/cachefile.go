// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package filesession implements the file format for session caches.
package filesession

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

var (
	// errUnsupportedVersion is returned (internally) when we encounter a version of the session cache file that we
	// don't understand how to handle (such as one produced by a future version of Pinniped).
	errUnsupportedVersion = fmt.Errorf("unsupported session version")
)

const (
	// apiVersion is the Kubernetes-style API version of the session file object.
	apiVersion = "config.supervisor.pinniped.dev/v1alpha1"

	// apiKind is the Kubernetes-style Kind of the session file object.
	apiKind = "SessionCache"

	// sessionExpiration is how long a session can remain unused before it is automatically pruned from the session cache.
	sessionExpiration = 90 * 24 * time.Hour
)

type (
	// sessionCache is the object which is YAML-serialized to form the contents of the cache file.
	sessionCache struct {
		metav1.TypeMeta
		Sessions []sessionEntry `json:"sessions"`
	}

	// sessionEntry is a single cache entry in the cache file.
	sessionEntry struct {
		Key               oidcclient.SessionCacheKey `json:"key"`
		CreationTimestamp metav1.Time                `json:"creationTimestamp"`
		LastUsedTimestamp metav1.Time                `json:"lastUsedTimestamp"`
		Tokens            oidctypes.Token            `json:"tokens"`
	}
)

// readSessionCache loads a sessionCache from a path on disk. If the requested path does not exist, it returns an empty cache.
func readSessionCache(path string) (*sessionCache, error) {
	cacheYAML, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If the file was not found, generate a freshly initialized empty cache.
			return emptySessionCache(), nil
		}
		// Otherwise bubble up the error.
		return nil, fmt.Errorf("could not read session file: %w", err)
	}

	// If we read the file successfully, unmarshal it from YAML.
	var cache sessionCache
	if err := yaml.Unmarshal(cacheYAML, &cache); err != nil {
		return nil, fmt.Errorf("invalid session file: %w", err)
	}

	// Validate that we're reading a version of the config we understand how to parse.
	if !(cache.TypeMeta.APIVersion == apiVersion && cache.TypeMeta.Kind == apiKind) { //nolint:staticcheck // De Morgan's doesn't make this more readable
		return nil, fmt.Errorf("%w: %#v", errUnsupportedVersion, cache.TypeMeta)
	}
	return &cache, nil
}

// emptySessionCache returns an empty, initialized sessionCache.
func emptySessionCache() *sessionCache {
	return &sessionCache{
		TypeMeta: metav1.TypeMeta{APIVersion: apiVersion, Kind: apiKind},
		Sessions: make([]sessionEntry, 0, 1),
	}
}

// writeTo writes the cache to the specified file path.
func (c *sessionCache) writeTo(path string) error {
	// Marshal the session back to YAML and save it to the file.
	cacheYAML, err := yaml.Marshal(c)
	if err == nil {
		err = os.WriteFile(path, cacheYAML, 0600)
	}
	return err
}

// normalized returns a copy of the sessionCache with stale entries removed and entries sorted in a canonical order.
func (c *sessionCache) normalized() *sessionCache {
	result := emptySessionCache()

	// Clean up expired/invalid tokens.
	now := time.Now()
	result.Sessions = make([]sessionEntry, 0, len(c.Sessions))

	for _, s := range c.Sessions {
		// Nil out any tokens that are empty or expired.
		if s.Tokens.IDToken != nil {
			if s.Tokens.IDToken.Token == "" || s.Tokens.IDToken.Expiry.Time.Before(now) {
				s.Tokens.IDToken = nil
			}
		}
		if s.Tokens.AccessToken != nil {
			if s.Tokens.AccessToken.Token == "" || s.Tokens.AccessToken.Expiry.Time.Before(now) {
				s.Tokens.AccessToken = nil
			}
		}
		if s.Tokens.RefreshToken != nil && s.Tokens.RefreshToken.Token == "" {
			s.Tokens.RefreshToken = nil
		}

		// Filter out any entries that no longer contain any tokens.
		if s.Tokens.IDToken == nil && s.Tokens.AccessToken == nil && s.Tokens.RefreshToken == nil {
			continue
		}

		// Filter out entries that haven't been used in the last sessionExpiration.
		cutoff := metav1.NewTime(now.Add(-1 * sessionExpiration))
		if s.LastUsedTimestamp.Before(&cutoff) {
			continue
		}

		result.Sessions = append(result.Sessions, s)
	}

	// Sort the sessions by creation time.
	sort.SliceStable(result.Sessions, func(i, j int) bool {
		return result.Sessions[i].CreationTimestamp.Before(&result.Sessions[j].CreationTimestamp)
	})

	return result
}

// lookup a cache entry by key. May return nil.
func (c *sessionCache) lookup(key oidcclient.SessionCacheKey) *sessionEntry {
	for i := range c.Sessions {
		if reflect.DeepEqual(c.Sessions[i].Key, key) {
			return &c.Sessions[i]
		}
	}
	return nil
}

// insert a cache entry.
func (c *sessionCache) insert(entries ...sessionEntry) {
	c.Sessions = slices.Concat(c.Sessions, entries)
}
