// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package filecredcache implements the file format for cluster credential caches.
package filecredcache

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"sigs.k8s.io/yaml"
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
	apiKind = "ClusterCredentialCache"

	// sessionExpiration is how long a session can remain unused before it is automatically pruned from the session cache.
	sessionExpiration = 24 * time.Hour
)

type (
	// credCache is the object which is YAML-serialized to form the contents of the cache file.
	credCache struct {
		metav1.TypeMeta
		Credentials []credEntry `json:"credentials"`
	}

	// credEntry is a single cache entry in the cache file.
	credEntry struct {
		Key               string                                           `json:"key"`
		CreationTimestamp metav1.Time                                      `json:"creationTimestamp"`
		LastUsedTimestamp metav1.Time                                      `json:"lastUsedTimestamp"`
		Credential        clientauthenticationv1beta1.ExecCredentialStatus `json:"credential"`
	}
)

// readCredCache loads a credCache from a path on disk. If the requested path does not exist, it returns an empty cache.
func readCredCache(path string) (*credCache, error) {
	cacheYAML, err := ioutil.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// If the file was not found, generate a freshly initialized empty cache.
			return emptyCredCache(), nil
		}
		// Otherwise bubble up the error.
		return nil, fmt.Errorf("could not read credential cache file: %w", err)
	}

	// If we read the file successfully, unmarshal it from YAML.
	var cache credCache
	if err := yaml.Unmarshal(cacheYAML, &cache); err != nil {
		return nil, fmt.Errorf("invalid credential cache file: %w", err)
	}

	// Validate that we're reading a version of the config we understand how to parse.
	if !(cache.TypeMeta.APIVersion == apiVersion && cache.TypeMeta.Kind == apiKind) {
		return nil, fmt.Errorf("%w: %#v", errUnsupportedVersion, cache.TypeMeta)
	}
	return &cache, nil
}

// emptyCredCache returns an empty, initialized credCache.
func emptyCredCache() *credCache {
	return &credCache{
		TypeMeta:    metav1.TypeMeta{APIVersion: apiVersion, Kind: apiKind},
		Credentials: make([]credEntry, 0, 1),
	}
}

// writeTo writes the cache to the specified file path.
func (c *credCache) writeTo(path string) error {
	// Marshal the session back to YAML and save it to the file.
	cacheYAML, err := yaml.Marshal(c)
	if err == nil {
		err = ioutil.WriteFile(path, cacheYAML, 0600)
	}
	return err
}

// normalized returns a copy of the credCache with stale entries removed and entries sorted in a canonical order.
func (c *credCache) normalized() *credCache {
	result := emptyCredCache()

	// Clean up expired/invalid tokens.
	now := time.Now()
	result.Credentials = make([]credEntry, 0, len(c.Credentials))

	for _, s := range c.Credentials {
		if s.Credential.ExpirationTimestamp != nil && s.Credential.ExpirationTimestamp.Time.Before(now) {
			continue
		}

		// this version of the client only understands certificate auth so discard anything without it
		if s.Credential.ClientCertificateData == "" || s.Credential.ClientKeyData == "" {
			continue
		}
		certPEM, err := base64.StdEncoding.DecodeString(s.Credential.ClientCertificateData)
		if err != nil {
			continue
		}
		keyPEM, err := base64.StdEncoding.DecodeString(s.Credential.ClientKeyData)
		if err != nil {
			continue
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			continue
		}
		if cert.NotAfter.Before(now) {
			continue
		}

		// Filter out entries that haven't been used in the last sessionExpiration.
		cutoff := metav1.NewTime(now.Add(-1 * sessionExpiration))
		if s.LastUsedTimestamp.Before(&cutoff) {
			continue
		}

		result.Credentials = append(result.Credentials, s)
	}

	// Sort the sessions by creation time.
	sort.SliceStable(result.Credentials, func(i, j int) bool {
		return result.Credentials[i].CreationTimestamp.Before(&result.Credentials[j].CreationTimestamp)
	})

	return result
}

// lookup a cache entry by key. May return nil.
func (c *credCache) lookup(key string) *credEntry {
	for i := range c.Credentials {
		if subtle.ConstantTimeCompare([]byte(key), []byte(c.Credentials[i].Key)) == 1 {
			return &c.Credentials[i]
		}
	}
	return nil
}

// insert a cache entry.
func (c *credCache) insert(entries ...credEntry) {
	c.Credentials = append(c.Credentials, entries...)
}
