// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idplister

import (
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
)

type UpstreamOIDCIdentityProvidersLister interface {
	GetOIDCIdentityProviders() []upstreamprovider.UpstreamOIDCIdentityProviderI
}

type UpstreamLDAPIdentityProvidersLister interface {
	GetLDAPIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI
}

type UpstreamActiveDirectoryIdentityProviderLister interface {
	GetActiveDirectoryIdentityProviders() []upstreamprovider.UpstreamLDAPIdentityProviderI
}

type UpstreamIdentityProvidersLister interface {
	UpstreamOIDCIdentityProvidersLister
	UpstreamLDAPIdentityProvidersLister
	UpstreamActiveDirectoryIdentityProviderLister
}
