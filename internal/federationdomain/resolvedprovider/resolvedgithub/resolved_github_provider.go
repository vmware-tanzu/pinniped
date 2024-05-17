// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
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

func (p *FederationDomainResolvedGitHubIdentityProvider) CloneIDPSpecificSessionDataFromSession(session *psession.CustomSessionData) interface{} {
	if session.GitHub == nil {
		return nil
	}
	return session.GitHub.Clone()
}

func (p *FederationDomainResolvedGitHubIdentityProvider) ApplyIDPSpecificSessionDataToSession(session *psession.CustomSessionData, idpSpecificSessionData interface{}) {
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
	redirectURL := upstreamOAuthConfig.AuthCodeURL(state.EncodedStateParam)
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
	token, _ := p.Provider.ExchangeAuthcode(
		ctx,
		authCode,
		redirectURI,
	)

	return &resolvedprovider.Identity{
			UpstreamUsername:  "some-github-login",
			UpstreamGroups:    []string{"org1/team1", "org2/team2"},
			DownstreamSubject: "https://github.com?idpName=upstream-github-idp-name&sub=some-github-login",
			IDPSpecificSessionData: &psession.GitHubSessionData{
				UpstreamAccessToken: token,
			},
		},
		&resolvedprovider.IdentityLoginExtras{},
		nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) UpstreamRefresh(
	_ context.Context,
	_ *resolvedprovider.Identity,
) (refreshedIdentity *resolvedprovider.RefreshedIdentity, err error) {
	return nil, errors.New("function UpstreamRefresh not yet implemented for GitHub IDP")
}
