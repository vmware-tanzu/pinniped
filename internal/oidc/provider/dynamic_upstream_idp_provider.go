// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"net/url"
	"sync"
)

type UpstreamOIDCIdentityProvider struct {
	// A name for this upstream provider, which will be used as a component of the path for the callback endpoint
	// hosted by the Supervisor.
	Name string

	// The Oauth client ID registered with the upstream provider to be used in the authorization flow.
	ClientID string

	// The Authorization Endpoint fetched from discovery.
	AuthorizationURL url.URL

	// Scopes to request in authorization flow.
	Scopes []string
}

type DynamicUpstreamIDPProvider interface {
	SetIDPList(oidcIDPs []UpstreamOIDCIdentityProvider)
	GetIDPList() []UpstreamOIDCIdentityProvider
}

type dynamicUpstreamIDPProvider struct {
	oidcProviders []UpstreamOIDCIdentityProvider
	mutex         sync.RWMutex
}

func NewDynamicUpstreamIDPProvider() DynamicUpstreamIDPProvider {
	return &dynamicUpstreamIDPProvider{
		oidcProviders: []UpstreamOIDCIdentityProvider{},
	}
}

func (p *dynamicUpstreamIDPProvider) SetIDPList(oidcIDPs []UpstreamOIDCIdentityProvider) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.oidcProviders = oidcIDPs
}

func (p *dynamicUpstreamIDPProvider) GetIDPList() []UpstreamOIDCIdentityProvider {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.oidcProviders
}
