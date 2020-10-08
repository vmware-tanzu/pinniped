// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"net/url"
	"strings"

	"go.pinniped.dev/internal/constable"
)

// OIDCProvider represents all of the settings and state for an OIDC provider.
type OIDCProvider struct {
	issuer     string
	issuerHost string
	issuerPath string
}

func NewOIDCProvider(issuer string) (*OIDCProvider, error) {
	p := OIDCProvider{issuer: issuer}
	err := p.validate()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *OIDCProvider) validate() error {
	if p.issuer == "" {
		return constable.Error("provider must have an issuer")
	}

	issuerURL, err := url.Parse(p.issuer)
	if err != nil {
		return fmt.Errorf("could not parse issuer as URL: %w", err)
	}

	if issuerURL.Scheme != "https" && p.removeMeAfterWeNoLongerNeedHTTPIssuerSupport(issuerURL.Scheme) {
		return constable.Error(`issuer must have "https" scheme`)
	}

	if issuerURL.User != nil {
		return constable.Error(`issuer must not have username or password`)
	}

	if strings.HasSuffix(issuerURL.Path, "/") {
		return constable.Error(`issuer must not have trailing slash in path`)
	}

	if issuerURL.RawQuery != "" {
		return constable.Error(`issuer must not have query`)
	}

	if issuerURL.Fragment != "" {
		return constable.Error(`issuer must not have fragment`)
	}

	p.issuerHost = issuerURL.Host
	p.issuerPath = issuerURL.Path

	return nil
}

func (p *OIDCProvider) Issuer() string {
	return p.issuer
}

func (p *OIDCProvider) IssuerHost() string {
	return p.issuerHost
}

func (p *OIDCProvider) IssuerPath() string {
	return p.issuerPath
}

func (p *OIDCProvider) removeMeAfterWeNoLongerNeedHTTPIssuerSupport(scheme string) bool {
	return scheme != "http"
}
