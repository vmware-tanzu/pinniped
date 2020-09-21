// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idpcache implements a cache of active identity providers.
package idpcache

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	loginapi "go.pinniped.dev/generated/1.19/apis/login"
)

var (
	// ErrNoSuchIDP is returned by Cache.AuthenticateTokenCredentialRequest() when the requested IDP is not configured.
	ErrNoSuchIDP = fmt.Errorf("no such identity provider")
)

// Cache implements the authenticator.Token interface by multiplexing across a dynamic set of identity providers
// loaded from IDP resources.
type Cache struct {
	cache sync.Map
}

type Key struct {
	APIGroup  string
	Kind      string
	Namespace string
	Name      string
}

type Value interface {
	authenticator.Token
}

// New returns an empty cache.
func New() *Cache {
	return &Cache{}
}

// Get an identity provider by key.
func (c *Cache) Get(key Key) Value {
	res, _ := c.cache.Load(key)
	if res == nil {
		return nil
	}
	return res.(Value)
}

// Store an identity provider into the cache.
func (c *Cache) Store(key Key, value Value) {
	c.cache.Store(key, value)
}

// Delete an identity provider from the cache.
func (c *Cache) Delete(key Key) {
	c.cache.Delete(key)
}

// Keys currently stored in the cache.
func (c *Cache) Keys() []Key {
	var result []Key
	c.cache.Range(func(key, _ interface{}) bool {
		result = append(result, key.(Key))
		return true
	})
	return result
}

func (c *Cache) AuthenticateTokenCredentialRequest(ctx context.Context, req *loginapi.TokenCredentialRequest) (user.Info, error) {
	// Map the incoming request to a cache key.
	key := Key{
		Namespace: req.Namespace,
		Name:      req.Spec.IdentityProvider.Name,
		Kind:      req.Spec.IdentityProvider.Kind,
	}
	if req.Spec.IdentityProvider.APIGroup != nil {
		key.APIGroup = *req.Spec.IdentityProvider.APIGroup
	}

	val := c.Get(key)
	if val == nil {
		return nil, ErrNoSuchIDP
	}

	// The incoming context could have an audience. Since we do not want to handle audiences right now, do not pass it
	// through directly to the authentication webhook.
	ctx = valuelessContext{ctx}

	// Call the selected IDP.
	resp, authenticated, err := val.AuthenticateToken(ctx, req.Spec.Token)
	if err != nil {
		return nil, err
	}
	if !authenticated {
		return nil, nil
	}

	// Return the user.Info from the response (if it is non-nil).
	var respUser user.Info
	if resp != nil {
		respUser = resp.User
	}
	return respUser, nil
}

type valuelessContext struct{ context.Context }

func (valuelessContext) Value(interface{}) interface{} { return nil }
