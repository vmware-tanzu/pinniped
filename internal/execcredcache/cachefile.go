// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execcredcache

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"sigs.k8s.io/yaml"
)

var (
	// errUnsupportedVersion is returned (internally) when we encounter a version of the cache file that we
	// don't understand how to handle (such as one produced by a future version of Pinniped).
	errUnsupportedVersion = fmt.Errorf("unsupported credential cache version")
)

const (
	// apiVersion is the Kubernetes-style API version of the credential cache file object.
	apiVersion = "config.supervisor.pinniped.dev/v1alpha1"

	// apiKind is the Kubernetes-style Kind of the credential cache file object.
	apiKind = "CredentialCache"

	// maxCacheDuration is how long a credential can remain in the cache even if it's still otherwise valid.
	maxCacheDuration = 1 * time.Hour
)

type (
	// credCache is the object which is YAML-serialized to form the contents of the cache file.
	credCache struct {
		metav1.TypeMeta
		Entries []entry `json:"credentials"`
	}

	// entry is a single credential in the cache file.
	entry struct {
		Key               string                                            `json:"key"`
		CreationTimestamp metav1.Time                                       `json:"creationTimestamp"`
		LastUsedTimestamp metav1.Time                                       `json:"lastUsedTimestamp"`
		Credential        *clientauthenticationv1beta1.ExecCredentialStatus `json:"credential"`
	}
)

// readCache loads a credCache from a path on disk. If the requested path does not exist, it returns an empty cache.
func readCache(path string) (*credCache, error) {
	cacheYAML, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If the file was not found, generate a freshly initialized empty cache.
			return emptyCache(), nil
		}
		// Otherwise bubble up the error.
		return nil, fmt.Errorf("could not read cache file: %w", err)
	}

	// If we read the file successfully, unmarshal it from YAML.
	var cache credCache
	if err := yaml.Unmarshal(cacheYAML, &cache); err != nil {
		return nil, fmt.Errorf("invalid cache file: %w", err)
	}

	// Validate that we're reading a version of the config we understand how to parse.
	if !(cache.TypeMeta.APIVersion == apiVersion && cache.TypeMeta.Kind == apiKind) { //nolint:staticcheck // De Morgan's doesn't make this more readable
		return nil, fmt.Errorf("%w: %#v", errUnsupportedVersion, cache.TypeMeta)
	}
	return &cache, nil
}

// emptyCache returns an empty, initialized credCache.
func emptyCache() *credCache {
	return &credCache{
		TypeMeta: metav1.TypeMeta{APIVersion: apiVersion, Kind: apiKind},
		Entries:  make([]entry, 0, 1),
	}
}

// writeTo writes the cache to the specified file path.
func (c *credCache) writeTo(path string) error {
	// Marshal the cache back to YAML and save it to the file.
	cacheYAML, err := yaml.Marshal(c)
	if err == nil {
		err = os.WriteFile(path, cacheYAML, 0600)
	}
	return err
}

// normalized returns a copy of the credCache with stale entries removed and entries sorted in a canonical order.
func (c *credCache) normalized() *credCache {
	result := emptyCache()

	// Clean up expired/invalid tokens.
	now := time.Now()
	result.Entries = make([]entry, 0, len(c.Entries))

	for _, e := range c.Entries {
		// Eliminate any cache entries that are missing a credential or an expiration timestamp.
		if e.Credential == nil || e.Credential.ExpirationTimestamp == nil {
			continue
		}

		// Eliminate any expired credentials.
		if e.Credential.ExpirationTimestamp.Time.Before(time.Now()) {
			continue
		}

		// Eliminate any entries older than maxCacheDuration.
		if e.CreationTimestamp.Time.Before(now.Add(-maxCacheDuration)) {
			continue
		}
		result.Entries = append(result.Entries, e)
	}

	// Sort the entries by creation time.
	sort.SliceStable(result.Entries, func(i, j int) bool {
		return result.Entries[i].CreationTimestamp.Before(&result.Entries[j].CreationTimestamp)
	})

	return result
}
