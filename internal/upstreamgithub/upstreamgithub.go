// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamgithub implements an abstraction of upstream GitHub provider interactions.
package upstreamgithub

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"

	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/authenticators"
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

type Provider struct {
	c ProviderConfig
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &Provider{}
var _ authenticators.UserAuthenticator = &Provider{}

// New creates a Provider. The config is not a pointer to ensure that a copy of the config is created,
// making the resulting Provider use an effectively read-only configuration.
func New(config ProviderConfig) *Provider {
	return &Provider{c: config}
}

// GetConfig is a reader for the config. Returns a copy of the config to keep the underlying config read-only.
func (p *Provider) GetConfig() ProviderConfig {
	return p.c
}

// GetName returns a name for this upstream provider.
func (p *Provider) GetName() string {
	return p.c.Name
}

func (p *Provider) GetResourceUID() types.UID {
	return p.c.ResourceUID
}

func (p *Provider) GetClientID() string {
	return p.c.OAuth2Config.ClientID
}

func (p *Provider) GetOAuth2Config() *oauth2.Config {
	return p.c.OAuth2Config
}

func (p *Provider) GetHost() string {
	return p.c.Host
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

func (p *Provider) GetOrganizationLoginPolicy() v1alpha1.GitHubAllowedAuthOrganizationsPolicy {
	return p.c.OrganizationLoginPolicy
}

func (p *Provider) GetAuthorizationURL() string {
	return p.c.AuthorizationURL
}

func (p *Provider) GetHttpClient() *http.Client {
	return p.c.HttpClient
}

// AuthenticateUser authenticates an end user and returns their mapped username, groups, and UID. Implements authenticators.UserAuthenticator.
func (p *Provider) AuthenticateUser(
	ctx context.Context,       //nolint:all
	username, password string, //nolint:all
) (*authenticators.Response, bool, error) {
	// TODO: implement this, currently just placeholder to satisfy UserAuthenticator interface above
	return nil, false, nil
}
