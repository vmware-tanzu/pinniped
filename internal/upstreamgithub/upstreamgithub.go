// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamgithub implements an abstraction of upstream GitHub provider interactions.
package upstreamgithub

import (
	"net/http"

	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
)

// ProviderConfig holds the active configuration of an upstream GitHub provider.
type ProviderConfig struct {
	Name                    string
	ResourceUID             types.UID
	Host                    string
	UsernameAttribute       v1alpha1.GitHubUsernameAttribute
	GroupNameAttribute      v1alpha1.GitHubGroupNameAttribute
	OAuth2Config            *oauth2.Config
	AllowedOrganizations    []string
	OrganizationLoginPolicy v1alpha1.GitHubAllowedAuthOrganizationsPolicy
	AuthorizationURL        string
	HttpClient              *http.Client
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = (*ProviderConfig)(nil)

func (p *ProviderConfig) GetResourceUID() types.UID {
	return p.ResourceUID
}

func (p *ProviderConfig) GetName() string {
	return p.Name
}

func (p *ProviderConfig) GetClientID() string {
	return p.OAuth2Config.ClientID
}

func (p *ProviderConfig) GetHost() string {
	return p.Host
}

func (p *ProviderConfig) GetUsernameAttribute() v1alpha1.GitHubUsernameAttribute {
	return p.UsernameAttribute
}

func (p *ProviderConfig) GetGroupNameAttribute() v1alpha1.GitHubGroupNameAttribute {
	return p.GroupNameAttribute
}

func (p *ProviderConfig) GetAllowedOrganizations() []string {
	return p.AllowedOrganizations
}

func (p *ProviderConfig) GetOrganizationLoginPolicy() v1alpha1.GitHubAllowedAuthOrganizationsPolicy {
	return p.OrganizationLoginPolicy
}

func (p *ProviderConfig) GetAuthorizationURL() string {
	return p.AuthorizationURL
}

func (p *ProviderConfig) GetHttpClient() *http.Client {
	return p.HttpClient
}
