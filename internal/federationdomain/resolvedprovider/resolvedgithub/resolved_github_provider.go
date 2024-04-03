// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// FederationDomainResolvedGitHubIdentityProvider respresents a FederationDomainIdentityProvider which has
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
	// TODO: implement
	return []v1alpha1.IDPFlow{}
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
	state *resolvedprovider.UpstreamAuthorizeRequestState, //nolint:all
	downstreamIssuerURL string, //nolint:all
) (string, error) {
	// TODO: implement
	return "", nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) Login(
	ctx context.Context, //nolint:all
	submittedUsername string, //nolint:all
	submittedPassword string, //nolint:all
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	// TODO: implement
	return nil, nil, nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) LoginFromCallback(
	ctx context.Context, //nolint:all
	authCode string, //nolint:all
	pkce pkce.Code, //nolint:all
	nonce nonce.Nonce, //nolint:all
	redirectURI string, //nolint:all
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	// TODO: implement
	return nil, nil, nil
}

func (p *FederationDomainResolvedGitHubIdentityProvider) UpstreamRefresh(
	ctx context.Context, //nolint:all
	identity *resolvedprovider.Identity, //nolint:all
) (refreshedIdentity *resolvedprovider.RefreshedIdentity, err error) {
	// TODO: implement
	return nil, nil
}
