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
	Name        string
	ResourceUID types.UID

	// APIBaseURL is the url of the GitHub API, not including the path to a specific API endpoint.
	// According to the GitHub docs, it should be either https://api.github.com/ for cloud
	// or https://HOSTNAME/api/v3/ for Enterprise Server.
	APIBaseURL string

	UsernameAttribute  v1alpha1.GitHubUsernameAttribute
	GroupNameAttribute v1alpha1.GitHubGroupNameAttribute

	// AllowedOrganizations, when empty, means to allow users from all orgs.
	AllowedOrganizations []string

	// HttpClient is a client that can be used to call the GitHub APIs and token endpoint.
	// This client should be configured with the user-provided CA bundle and a timeout.
	HttpClient *http.Client

	// OAuth2Config contains ClientID, ClientSecret, Scopes, and Endpoint (which contains auth and token endpoint URLs,
	// and auth style for the token endpoint).
	// OAuth2Config will not be used to compute the authorize URL because the redirect back to the Supervisor's
	// callback must be different per FederationDomain. It holds data that may be useful when calculating the
	// authorize URL, so that data is exposed by interface methods. However, it can be used to call the token endpoint,
	// for which there is no RedirectURL needed.
	OAuth2Config *oauth2.Config
}

type Provider struct {
	c ProviderConfig
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &Provider{}

// New creates a Provider. The config is not a pointer to ensure that a copy of the config is created,
// making the resulting Provider use an effectively read-only configuration.
func New(config ProviderConfig) *Provider {
	return &Provider{c: config}
}

func (p *Provider) GetName() string {
	return p.c.Name
}

func (p *Provider) GetResourceUID() types.UID {
	return p.c.ResourceUID
}

func (p *Provider) GetClientID() string {
	return p.c.OAuth2Config.ClientID
}

func (p *Provider) GetScopes() []string {
	return p.c.OAuth2Config.Scopes
}

func (p *Provider) GetUsernameAttribute() v1alpha1.GitHubUsernameAttribute {
	return p.c.UsernameAttribute
}

func (p *Provider) GetGroupNameAttribute() v1alpha1.GitHubGroupNameAttribute {
	return p.c.GroupNameAttribute
}

func (p *Provider) GetAllowedOrganizations() []string {
	return p.c.AllowedOrganizations
}

func (p *Provider) GetAuthorizationURL() string {
	return p.c.OAuth2Config.Endpoint.AuthURL
}

// GetConfig returns the config. This is not part of the interface and is mostly just for testing.
func (p *Provider) GetConfig() ProviderConfig {
	return p.c
}
