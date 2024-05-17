// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamgithub implements an abstraction of upstream GitHub provider interactions.
package upstreamgithub

import (
	"context"
	"net/http"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
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

func (p *Provider) ExchangeAuthcode(ctx context.Context, authcode string, redirectURI string) (string, error) {
	// TODO: write tests for this
	panic("write some tests for this sketch of the implementation, maybe by running a test server in the unit tests")
	//nolint:govet // this code is intentionally unreachable until we resolve the todos
	tok, err := p.c.OAuth2Config.Exchange(
		coreosoidc.ClientContext(ctx, p.c.HttpClient),
		authcode,
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
	)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

func (p *Provider) GetUser(_ctx context.Context, _accessToken string) (*upstreamprovider.GitHubUser, error) {
	// TODO Implement this to make several https calls to github to learn about the user, using a lower-level githubclient package.
	//   Pass the ctx, accessToken, p.c.HttpClient, and p.c.APIBaseURL to the lower-level package's functions.
	// TODO: Reject the auth if the user does not belong to any of p.c.AllowedOrganizations (unless p.c.AllowedOrganizations is empty).
	// TODO: Make use of p.c.UsernameAttribute and p.c.GroupNameAttribute when deciding the username and group names.
	// TODO: Determine the downstream subject by first writing a helper in downstream_subject.go and then calling it here.
	panic("implement me")
	//nolint:govet // this code is intentionally unreachable until we resolve the todos
	return &upstreamprovider.GitHubUser{
		Username:          "TODO",
		Groups:            []string{"org/TODO"},
		DownstreamSubject: "TODO",
	}, nil
}

// GetConfig returns the config. This is not part of the UpstreamGithubIdentityProviderI interface and is just for testing.
func (p *Provider) GetConfig() ProviderConfig {
	return p.c
}
