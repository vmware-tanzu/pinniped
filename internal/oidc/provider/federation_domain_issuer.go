// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"net/url"
	"strings"

	"go.pinniped.dev/internal/constable"
)

// FederationDomainIssuer represents all the settings and state for a downstream OIDC provider
// as defined by a FederationDomain.
type FederationDomainIssuer struct {
	issuer     string
	issuerHost string
	issuerPath string
}

// NewFederationDomainIssuer returns a FederationDomainIssuer.
// Performs validation, and returns any error from validation.
func NewFederationDomainIssuer(issuer string) (*FederationDomainIssuer, error) {
	p := FederationDomainIssuer{issuer: issuer}
	err := p.validate()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *FederationDomainIssuer) validate() error {
	if p.issuer == "" {
		return constable.Error("federation domain must have an issuer")
	}

	issuerURL, err := url.Parse(p.issuer)
	if err != nil {
		return fmt.Errorf("could not parse issuer as URL: %w", err)
	}

	if issuerURL.Scheme != "https" {
		return constable.Error(`issuer must have "https" scheme`)
	}

	if issuerURL.Hostname() == "" {
		return constable.Error(`issuer must have a hostname`)
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

// Issuer returns the issuer
func (p *FederationDomainIssuer) Issuer() string {
	return p.issuer
}

// IssuerHost returns the issuerHost
func (p *FederationDomainIssuer) IssuerHost() string {
	return p.issuerHost
}

// IssuerPath returns the issuerPath
func (p *FederationDomainIssuer) IssuerPath() string {
	return p.issuerPath
}
