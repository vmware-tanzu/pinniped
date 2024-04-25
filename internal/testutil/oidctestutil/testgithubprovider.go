// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"net/http"

	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
)

type TestUpstreamGitHubIdentityProviderBuilder struct {
	name                           string
	clientID                       string
	resourceUID                    types.UID
	displayNameForFederationDomain string
	transformsForFederationDomain  *idtransform.TransformationPipeline
	usernameAttribute              v1alpha1.GitHubUsernameAttribute
	groupNameAttribute             v1alpha1.GitHubGroupNameAttribute
	allowedOrganizations           []string
	organizationLoginPolicy        v1alpha1.GitHubAllowedAuthOrganizationsPolicy
	authorizationURL               string
	httpClient                     *http.Client
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

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithOrganizationLoginPolicy(value v1alpha1.GitHubAllowedAuthOrganizationsPolicy) *TestUpstreamGitHubIdentityProviderBuilder {
	u.organizationLoginPolicy = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithAuthorizationURL(value string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.authorizationURL = value
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithHttpClient(value *http.Client) *TestUpstreamGitHubIdentityProviderBuilder {
	u.httpClient = value
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
		DisplayNameForFederationDomain: u.displayNameForFederationDomain,
		TransformsForFederationDomain:  u.transformsForFederationDomain,
		UsernameAttribute:              u.usernameAttribute,
		GroupNameAttribute:             u.groupNameAttribute,
		AllowedOrganizations:           u.allowedOrganizations,
		OrganizationLoginPolicy:        u.organizationLoginPolicy,
		AuthorizationURL:               u.authorizationURL,
		HttpClient:                     u.httpClient,
	}
}

func NewTestUpstreamGitHubIdentityProviderBuilder() *TestUpstreamGitHubIdentityProviderBuilder {
	return &TestUpstreamGitHubIdentityProviderBuilder{}
}

type TestUpstreamGitHubIdentityProvider struct {
	Name                           string
	ClientID                       string
	ResourceUID                    types.UID
	Host                           string
	DisplayNameForFederationDomain string
	TransformsForFederationDomain  *idtransform.TransformationPipeline
	UsernameAttribute              v1alpha1.GitHubUsernameAttribute
	GroupNameAttribute             v1alpha1.GitHubGroupNameAttribute
	AllowedOrganizations           []string
	OrganizationLoginPolicy        v1alpha1.GitHubAllowedAuthOrganizationsPolicy
	AuthorizationURL               string
	HttpClient                     *http.Client
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &TestUpstreamGitHubIdentityProvider{}

func (u *TestUpstreamGitHubIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamGitHubIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamGitHubIdentityProvider) GetHost() string {
	return u.Host
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

func (u *TestUpstreamGitHubIdentityProvider) GetOrganizationLoginPolicy() v1alpha1.GitHubAllowedAuthOrganizationsPolicy {
	return u.OrganizationLoginPolicy
}

func (u *TestUpstreamGitHubIdentityProvider) GetAuthorizationURL() string {
	return u.AuthorizationURL
}

func (u *TestUpstreamGitHubIdentityProvider) GetHttpClient() *http.Client {
	return u.HttpClient
}
