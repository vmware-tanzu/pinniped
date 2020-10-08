// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"net/url"
	"strings"

	"go.pinniped.dev/internal/constable"
)

// OIDCProvider represents all of the settings and state for an OIDC provider.
type OIDCProvider struct {
	Issuer *url.URL
}

// Validate returns an error if there is anything wrong with the provider settings, or
// returns nil if there is nothing wrong with the settings.
func (p *OIDCProvider) Validate() error {
	if p.Issuer == nil {
		return constable.Error(`provider must have an issuer`)
	}

	if p.Issuer.Scheme != "https" && p.removeMeAfterWeNoLongerNeedHTTPIssuerSupport(p.Issuer.Scheme) {
		return constable.Error(`issuer must have "https" scheme`)
	}

	if p.Issuer.User != nil {
		return constable.Error(`issuer must not have username or password`)
	}

	if strings.HasSuffix(p.Issuer.Path, "/") {
		return constable.Error(`issuer must not have trailing slash in path`)
	}

	if p.Issuer.RawQuery != "" {
		return constable.Error(`issuer must not have query`)
	}

	if p.Issuer.Fragment != "" {
		return constable.Error(`issuer must not have fragment`)
	}

	return nil
}

func (p *OIDCProvider) removeMeAfterWeNoLongerNeedHTTPIssuerSupport(scheme string) bool {
	return scheme != "http"
}
