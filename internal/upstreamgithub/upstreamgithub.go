// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamgithub implements an abstraction of upstream GitHub provider interactions.
package upstreamgithub

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	supervisoridpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/downstreamsubject"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/githubclient"
)

// ProviderConfig holds the active configuration of an upstream GitHub provider.
type ProviderConfig struct {
	Name        string
	ResourceUID types.UID

	// APIBaseURL is the url of the GitHub API, not including the path to a specific API endpoint.
	// According to the GitHub docs, it should be either https://api.github.com/ for cloud
	// or https://HOSTNAME/api/v3/ for Enterprise Server.
	APIBaseURL string

	UsernameAttribute  supervisoridpv1alpha1.GitHubUsernameAttribute
	GroupNameAttribute supervisoridpv1alpha1.GitHubGroupNameAttribute

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
	c                 ProviderConfig
	buildGitHubClient func(httpClient *http.Client, apiBaseURL, token string) (githubclient.GitHubInterface, error)
}

var _ upstreamprovider.UpstreamGithubIdentityProviderI = &Provider{}

// New creates a Provider. The config is not a pointer to ensure that a copy of the config is created,
// making the resulting Provider use an effectively read-only configuration.
func New(config ProviderConfig) *Provider {
	return &Provider{
		c:                 config,
		buildGitHubClient: githubclient.NewGitHubClient,
	}
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

func (p *Provider) GetUsernameAttribute() supervisoridpv1alpha1.GitHubUsernameAttribute {
	return p.c.UsernameAttribute
}

func (p *Provider) GetGroupNameAttribute() supervisoridpv1alpha1.GitHubGroupNameAttribute {
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

// GetUser will use the provided configuration to make HTTPS calls to the GitHub API to find out who the logged-in user is,
// what organizations they belong to, and what teams they belong to.
// If the user's information meets the AllowedOrganization criteria specified on the GitHubIdentityProvider, they will be
// allowed to log in.
// Note that errors from the githubclient package already have helpful error prefixes, so there is no need for additional prefixes here.
// TODO: populate the IDP display name
// TODO: What should we do if the group or team name is outside of the enum? The controller would reject this.
// TODO: should we use the APIBaseURL or some other URL in the downstreamSubject
//
// Examples:
//
//	"github.com" or "https://github.com" or "https://api.github.com"?
//	"enterprise.tld" or "https://enterprise.tld" or "https://enterprise.tld/api/v3"?
func (p *Provider) GetUser(ctx context.Context, accessToken string) (*upstreamprovider.GitHubUser, error) {
	githubClient, err := p.buildGitHubClient(p.c.HttpClient, p.c.APIBaseURL, accessToken)
	if err != nil {
		return nil, err
	}

	githubUser := upstreamprovider.GitHubUser{}

	userInfo, err := githubClient.GetUserInfo(ctx)
	if err != nil {
		return nil, err
	}

	githubUser.DownstreamSubject = downstreamsubject.GitHub(p.c.APIBaseURL, "TODO_IDP_DISPLAY_NAME", userInfo.Login, userInfo.ID)

	switch p.c.UsernameAttribute {
	case supervisoridpv1alpha1.GitHubUsernameLoginAndID:
		githubUser.Username = fmt.Sprintf("%s:%s", userInfo.Login, userInfo.ID)
	case supervisoridpv1alpha1.GitHubUsernameLogin:
		githubUser.Username = userInfo.Login
	case supervisoridpv1alpha1.GitHubUsernameID:
		githubUser.Username = userInfo.ID
	}

	orgMembership, err := githubClient.GetOrgMembership(ctx)
	if err != nil {
		return nil, err
	}

	allowedOrgs := sets.New[string](p.c.AllowedOrganizations...)

	if allowedOrgs.Len() > 0 && allowedOrgs.Intersection(orgMembership).Len() < 1 {
		return nil, errors.New("user is not allowed to log in due to organization membership policy")
	}

	teamMembership, err := githubClient.GetTeamMembership(ctx, allowedOrgs)
	if err != nil {
		return nil, err
	}

	for _, team := range teamMembership {
		downstreamGroup := ""

		switch p.c.GroupNameAttribute {
		case supervisoridpv1alpha1.GitHubUseTeamNameForGroupName:
			downstreamGroup = fmt.Sprintf("%s/%s", team.Org, team.Name)
		case supervisoridpv1alpha1.GitHubUseTeamSlugForGroupName:
			downstreamGroup = fmt.Sprintf("%s/%s", team.Org, team.Slug)
		}

		githubUser.Groups = append(githubUser.Groups, downstreamGroup)
	}

	return &githubUser, nil
}

// GetConfig returns the config. This is not part of the UpstreamGithubIdentityProviderI interface and is just for testing.
func (p *Provider) GetConfig() ProviderConfig {
	return p.c
}
