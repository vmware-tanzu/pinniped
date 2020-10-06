// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package issuerprovider provides a thread-safe type that can hold on to an OIDC issuer name.
package issuerprovider

import "sync"

// Provider is a type that can hold onto an issuer value, which may be nil.
//
// It is thread-safe.
type Provider struct {
	mu     sync.RWMutex
	issuer *string
}

// New returns an empty Provider, i.e., one that holds a nil issuer.
func New() *Provider {
	return &Provider{}
}

func (p *Provider) SetIssuer(issuer *string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuer = issuer
}

func (p *Provider) GetIssuer() *string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.issuer
}
