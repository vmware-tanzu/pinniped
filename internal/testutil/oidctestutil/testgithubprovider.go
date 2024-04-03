// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
)

// TODO: flesh this out.
type TestUpstreamGitHubIdentityProviderBuilder struct {
	name                           string
	clientID                       string
	resourceUID                    types.UID
	displayNameForFederationDomain string
	transformsForFederationDomain  *idtransform.TransformationPipeline
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithName(value string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.name = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithResourceUID(value types.UID) *TestUpstreamGitHubIdentityProviderBuilder {
	u.resourceUID = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithClientID(value string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.clientID = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) Build() *TestUpstreamGitHubIdentityProvider {
	if u.displayNameForFederationDomain == "" {
		// default it to the CR name
		u.displayNameForFederationDomain = u.name
	}
	if u.transformsForFederationDomain == nil {
		// default to an empty pipeline
		u.transformsForFederationDomain = idtransform.NewTransformationPipeline()
	}
	// TODO: flesh this out.
	return &TestUpstreamGitHubIdentityProvider{
		Name:                           u.name,
		ResourceUID:                    u.resourceUID,
		ClientID:                       u.clientID,
		DisplayNameForFederationDomain: u.displayNameForFederationDomain,
		TransformsForFederationDomain:  u.transformsForFederationDomain,
	}
}

func NewTestUpstreamGitHubIdentityProviderBuilder() *TestUpstreamGitHubIdentityProviderBuilder {
	return &TestUpstreamGitHubIdentityProviderBuilder{}
}

// TODO: flesh this out.
type TestUpstreamGitHubIdentityProvider struct {
	Name                           string
	ClientID                       string
	ResourceUID                    types.UID
	DisplayNameForFederationDomain string
	TransformsForFederationDomain  *idtransform.TransformationPipeline
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &TestUpstreamGitHubIdentityProvider{}

func (u *TestUpstreamGitHubIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamGitHubIdentityProvider) GetName() string {
	return u.Name
}
