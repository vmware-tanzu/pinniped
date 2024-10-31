// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ory/fosite"
	"golang.org/x/oauth2"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// FederationDomainResolvedGitHubIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamGitHubIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedGitHubIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamGithubIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

var _ resolvedprovider.FederationDomainResolvedIdentityProvider = (*FederationDomainResolvedGitHubIdentityProvider)(nil)

func (p *FederationDomainResolvedGitHubIdentityProvider) GetDisplayName() string {
	return p.DisplayName
}

func (p *FederationDomainResolvedGitHubIdentityProvider) GetProvider() upstreamprovider.UpstreamIdentityProviderI {
	return p.Provider
}

func (p *FederationDomainResolvedGitHubIdentityProvider) GetSessionProviderType() psession.ProviderType {
	return p.SessionProviderType
}

func (p *FederationDomainResolvedGitHubIdentityProvider) GetIDPDiscoveryType() v1alpha1.IDPType {
	return v1alpha1.IDPTypeGitHub
}

func (p *FederationDomainResolvedGitHubIdentityProvider) GetIDPDiscoveryFlows() []v1alpha1.IDPFlow {
	return []v1alpha1.IDPFlow{v1alpha1.IDPFlowBrowserAuthcode}
}

func (p *FederationDomainResolvedGitHubIdentityProvider) GetTransforms() *idtransform.TransformationPipeline {
	return p.Transforms
}

func (p *FederationDomainResolvedGitHubIdentityProvider) CloneIDPSpecificSessionDataFromSession(session *psession.CustomSessionData) any {
	if session.GitHub == nil {
		return nil
	}
	return session.GitHub.Clone()
}

func (p *FederationDomainResolvedGitHubIdentityProvider) ApplyIDPSpecificSessionDataToSession(session *psession.CustomSessionData, idpSpecificSessionData any) {
	session.GitHub = idpSpecificSessionData.(*psession.GitHubSessionData)
}

func (p *FederationDomainResolvedGitHubIdentityProvider) UpstreamAuthorizeRedirectURL(
	state *resolvedprovider.UpstreamAuthorizeRequestState,
	downstreamIssuerURL string,
) (string, error) {
	upstreamOAuthConfig := oauth2.Config{
		ClientID: p.Provider.GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL: p.Provider.GetAuthorizationURL(),
		},
		RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuerURL),
		Scopes:      p.Provider.GetScopes(),
	}
	redirectURL := upstreamOAuthConfig.AuthCodeURL(state.EncodedStateParam.String())
	return redirectURL, nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) Login(
	_ context.Context,
	_ string,
	_ string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	return nil, nil, errors.New("function Login not yet implemented for GitHub IDP")
}

func (p *FederationDomainResolvedGitHubIdentityProvider) LoginFromCallback(
	ctx context.Context,
	authCode string,
	_ pkce.Code, // GitHub does not support PKCE, see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
	_ nonce.Nonce, // GitHub does not support OIDC, therefore there is no ID token that could contain the "nonce".
	redirectURI string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	accessToken, err := p.Provider.ExchangeAuthcode(ctx, authCode, redirectURI)
	if err != nil {
		return nil, nil, httperr.Wrap(http.StatusBadGateway,
			"failed to exchange authcode using GitHub API",
			err,
		)
	}

	user, err := p.Provider.GetUser(ctx, accessToken, p.GetDisplayName())

	if errors.As(err, &upstreamprovider.GitHubLoginDeniedError{}) {
		// We specifically want errors of type GitHubLoginDeniedError to have a user-displayed message.
		// Don't wrap the error since we include it in the sprintf here.
		return nil, nil, httperr.Newf(http.StatusForbidden,
			"login denied due to configuration on GitHubIdentityProvider with display name %q: %s",
			p.GetDisplayName(), err)
	} else if err != nil {
		return nil, nil, httperr.Wrap(http.StatusUnprocessableEntity,
			"failed to get user info from GitHub API",
			err,
		)
	}

	return &resolvedprovider.Identity{
			UpstreamUsername:  user.Username,
			UpstreamGroups:    user.Groups,
			DownstreamSubject: user.DownstreamSubject,
			IDPSpecificSessionData: &psession.GitHubSessionData{
				UpstreamAccessToken: accessToken,
			},
		},
		&resolvedprovider.IdentityLoginExtras{
			DownstreamAdditionalClaims: nil, // not using this for GitHub
			Warnings:                   nil, // not using this for GitHub
		},
		nil // no error
}

func (p *FederationDomainResolvedGitHubIdentityProvider) UpstreamRefresh(
	ctx context.Context,
	identity *resolvedprovider.Identity,
) (*resolvedprovider.RefreshedIdentity, error) {
	githubSessionData, ok := identity.IDPSpecificSessionData.(*psession.GitHubSessionData)
	if !ok {
		// This should not really happen.
		return nil, p.refreshErr(errors.New("wrong data type found for IDPSpecificSessionData"))
	}
	if len(githubSessionData.UpstreamAccessToken) == 0 {
		// This should not really happen.
		return nil, p.refreshErr(errors.New("session is missing GitHub access token"))
	}

	// Get the user's GitHub identity and groups again using the cached access token.
	refreshedUserInfo, err := p.Provider.GetUser(ctx, githubSessionData.UpstreamAccessToken, p.GetDisplayName())
	if err != nil {
		return nil, p.refreshErr(err)
	}

	if refreshedUserInfo.DownstreamSubject != identity.DownstreamSubject {
		// The user's upstream identity changed since the initial login in a surprising way.
		return nil, p.refreshErr(fmt.Errorf("user's calculated downstream subject at initial login was %q but now is %q",
			identity.DownstreamSubject, refreshedUserInfo.DownstreamSubject))
	}

	return &resolvedprovider.RefreshedIdentity{
		UpstreamUsername:       refreshedUserInfo.Username,
		UpstreamGroups:         refreshedUserInfo.Groups,
		IDPSpecificSessionData: nil, // nil means that no update to the GitHub-specific portion of the session data is required
	}, nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) refreshErr(err error) *fosite.RFC6749Error {
	return resolvedprovider.ErrUpstreamRefreshError().
		WithHint("Upstream refresh failed.").
		WithTrace(err).
		WithDebugf("provider name: %q, provider type: %q", p.Provider.GetResourceName(), p.GetSessionProviderType())
}
