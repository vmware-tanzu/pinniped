// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamoidc implements an abstraction of upstream GitHub provider interactions.
package upstreamgithub

import (
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
)

// ProviderConfig holds the active configuration of an upstream GitHub provider.
type ProviderConfig struct {
	Name          string
	ResourceUID   types.UID
	UsernameClaim string
	GroupsClaim   string
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = (*ProviderConfig)(nil)

func (p *ProviderConfig) GetResourceUID() types.UID {
	return p.ResourceUID
}

func (p *ProviderConfig) GetName() string {
	return p.Name
}
