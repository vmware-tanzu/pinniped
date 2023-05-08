// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"sync"

	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
)

type DynamicUpstreamIDPProvider interface {
	SetOIDCIdentityProviders(oidcIDPs []upstreamprovider.UpstreamOIDCIdentityProviderI)
	GetOIDCIdentityProviders() []upstreamprovider.UpstreamOIDCIdentityProviderI
	SetLDAPIdentityProviders(ldapIDPs []upstreamprovider.UpstreamLDAPIdentityProviderI)
	GetLDAPIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI
	SetActiveDirectoryIdentityProviders(adIDPs []upstreamprovider.UpstreamLDAPIdentityProviderI)
	GetActiveDirectoryIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI
}

type dynamicUpstreamIDPProvider struct {
	oidcUpstreams            []upstreamprovider.UpstreamOIDCIdentityProviderI
	ldapUpstreams            []upstreamprovider.UpstreamLDAPIdentityProviderI
	activeDirectoryUpstreams []upstreamprovider.UpstreamLDAPIdentityProviderI
	mutex                    sync.RWMutex
}

func NewDynamicUpstreamIDPProvider() DynamicUpstreamIDPProvider {
	return &dynamicUpstreamIDPProvider{
		oidcUpstreams:            []upstreamprovider.UpstreamOIDCIdentityProviderI{},
		ldapUpstreams:            []upstreamprovider.UpstreamLDAPIdentityProviderI{},
		activeDirectoryUpstreams: []upstreamprovider.UpstreamLDAPIdentityProviderI{},
	}
}

func (p *dynamicUpstreamIDPProvider) SetOIDCIdentityProviders(oidcIDPs []upstreamprovider.UpstreamOIDCIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.oidcUpstreams = oidcIDPs
}

func (p *dynamicUpstreamIDPProvider) GetOIDCIdentityProviders() []upstreamprovider.UpstreamOIDCIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.oidcUpstreams
}

func (p *dynamicUpstreamIDPProvider) SetLDAPIdentityProviders(ldapIDPs []upstreamprovider.UpstreamLDAPIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.ldapUpstreams = ldapIDPs
}

func (p *dynamicUpstreamIDPProvider) GetLDAPIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.ldapUpstreams
}

func (p *dynamicUpstreamIDPProvider) SetActiveDirectoryIdentityProviders(adIDPs []upstreamprovider.UpstreamLDAPIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.activeDirectoryUpstreams = adIDPs
}

func (p *dynamicUpstreamIDPProvider) GetActiveDirectoryIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.activeDirectoryUpstreams
}

type RetryableRevocationError struct {
	wrapped error
}

func NewRetryableRevocationError(wrapped error) RetryableRevocationError {
	return RetryableRevocationError{wrapped: wrapped}
}

func (e RetryableRevocationError) Error() string {
	return fmt.Sprintf("retryable revocation error: %v", e.wrapped)
}

func (e RetryableRevocationError) Unwrap() error {
	return e.wrapped
}
