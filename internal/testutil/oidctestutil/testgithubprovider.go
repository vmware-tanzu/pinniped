// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
)

type TestUpstreamGitHubIdentityProviderBuilder struct {
	name                           string
	resourceUID                    types.UID
	clientID                       string
	scopes                         []string
	displayNameForFederationDomain string
	transformsForFederationDomain  *idtransform.TransformationPipeline
	usernameAttribute              v1alpha1.GitHubUsernameAttribute
	groupNameAttribute             v1alpha1.GitHubGroupNameAttribute
	allowedOrganizations           []string
	authorizationURL               string
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

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithScopes(value []string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.scopes = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithDisplayNameForFederationDomain(value string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.displayNameForFederationDomain = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithUsernameAttribute(value v1alpha1.GitHubUsernameAttribute) *TestUpstreamGitHubIdentityProviderBuilder {
	u.usernameAttribute = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithGroupNameAttribute(value v1alpha1.GitHubGroupNameAttribute) *TestUpstreamGitHubIdentityProviderBuilder {
	u.groupNameAttribute = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithAllowedOrganizations(value []string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.allowedOrganizations = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithAuthorizationURL(value string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.authorizationURL = value
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
	return &TestUpstreamGitHubIdentityProvider{
		Name:                           u.name,
		ResourceUID:                    u.resourceUID,
		ClientID:                       u.clientID,
		Scopes:                         u.scopes,
		DisplayNameForFederationDomain: u.displayNameForFederationDomain,
		TransformsForFederationDomain:  u.transformsForFederationDomain,
		UsernameAttribute:              u.usernameAttribute,
		GroupNameAttribute:             u.groupNameAttribute,
		AllowedOrganizations:           u.allowedOrganizations,
		AuthorizationURL:               u.authorizationURL,
	}
}

func NewTestUpstreamGitHubIdentityProviderBuilder() *TestUpstreamGitHubIdentityProviderBuilder {
	return &TestUpstreamGitHubIdentityProviderBuilder{}
}

type TestUpstreamGitHubIdentityProvider struct {
	Name                           string
	ClientID                       string
	ResourceUID                    types.UID
	Scopes                         []string
	DisplayNameForFederationDomain string
	TransformsForFederationDomain  *idtransform.TransformationPipeline
	UsernameAttribute              v1alpha1.GitHubUsernameAttribute
	GroupNameAttribute             v1alpha1.GitHubGroupNameAttribute
	AllowedOrganizations           []string
	AuthorizationURL               string
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &TestUpstreamGitHubIdentityProvider{}

func (u *TestUpstreamGitHubIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamGitHubIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamGitHubIdentityProvider) GetScopes() []string {
	return u.Scopes
}

func (u *TestUpstreamGitHubIdentityProvider) GetClientID() string {
	return u.ClientID
}

func (u *TestUpstreamGitHubIdentityProvider) GetUsernameAttribute() v1alpha1.GitHubUsernameAttribute {
	return u.UsernameAttribute
}

func (u *TestUpstreamGitHubIdentityProvider) GetGroupNameAttribute() v1alpha1.GitHubGroupNameAttribute {
	return u.GroupNameAttribute
}

func (u *TestUpstreamGitHubIdentityProvider) GetAllowedOrganizations() []string {
	return u.AllowedOrganizations
}

func (u *TestUpstreamGitHubIdentityProvider) GetAuthorizationURL() string {
	return u.AuthorizationURL
}
