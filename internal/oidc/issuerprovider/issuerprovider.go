// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package issuerprovider provides a thread-safe type that can hold on to an OIDC issuer name.
package issuerprovider

import (
	"net/url"
	"strings"
	"sync"

	"go.pinniped.dev/internal/constable"
)

// Provider is a type that can hold onto an issuer value, which may be nil.
//
// It is thread-safe.
type Provider struct {
	mu     sync.RWMutex
	issuer *url.URL
}

// New returns an empty Provider, i.e., one that holds a nil issuer.
func New() *Provider {
	return &Provider{}
}

// SetIssuer validates and sets the provided issuer. If validation fails, SetIssuer will return
// an error.
func (p *Provider) SetIssuer(issuer *url.URL) error {
	if err := p.validateIssuer(issuer); err != nil {
		return err
	}
	p.setIssuer(issuer)
	return nil
}

func (p *Provider) validateIssuer(issuer *url.URL) error {
	if issuer == nil {
		return nil
	}

	if issuer.Scheme != "https" && removeMeAfterWeNoLongerNeedHTTPIssuerSupport(issuer.Scheme) {
		return constable.Error(`issuer must have "https" scheme`)
	}

	if issuer.User != nil {
		return constable.Error(`issuer must not have username or password`)
	}

	if strings.HasSuffix(issuer.Path, "/") {
		return constable.Error(`issuer must not have trailing slash in path`)
	}

	if issuer.RawQuery != "" {
		return constable.Error(`issuer must not have query`)
	}

	if issuer.Fragment != "" {
		return constable.Error(`issuer must not have fragment`)
	}

	return nil
}

func (p *Provider) setIssuer(issuer *url.URL) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuer = issuer
}

func (p *Provider) GetIssuer() *url.URL {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.issuer
}

func removeMeAfterWeNoLongerNeedHTTPIssuerSupport(scheme string) bool {
	return scheme != "http"
}
