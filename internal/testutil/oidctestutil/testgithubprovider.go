// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"

	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
)

// ExchangeAuthcodeArgs is used to spy on calls to
// TestUpstreamGitHubIdentityProvider.ExchangeAuthcodeFunc().
type ExchangeAuthcodeArgs struct {
	Ctx         context.Context
	Authcode    string
	RedirectURI string
}

// GetUserArgs is used to spy on calls to
// TestUpstreamGitHubIdentityProvider.GetUserFunc().
type GetUserArgs struct {
	Ctx         context.Context
	AccessToken string
}

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
	authcodeExchangeErr            error
	accessToken                    string
	getUserErr                     error
	getUserUser                    *upstreamprovider.GitHubUser
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

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithAccessToken(token string) *TestUpstreamGitHubIdentityProviderBuilder {
	u.accessToken = token
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithAuthcodeExchangeError(err error) *TestUpstreamGitHubIdentityProviderBuilder {
	u.authcodeExchangeErr = err
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithUser(user *upstreamprovider.GitHubUser) *TestUpstreamGitHubIdentityProviderBuilder {
	u.getUserUser = user
	return u
}

func (u *TestUpstreamGitHubIdentityProviderBuilder) WithGetUserError(err error) *TestUpstreamGitHubIdentityProviderBuilder {
	u.getUserErr = err
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
		ClientID:                       u.clientID,
		ResourceUID:                    u.resourceUID,
		Scopes:                         u.scopes,
		DisplayNameForFederationDomain: u.displayNameForFederationDomain,
		TransformsForFederationDomain:  u.transformsForFederationDomain,
		UsernameAttribute:              u.usernameAttribute,
		GroupNameAttribute:             u.groupNameAttribute,
		AllowedOrganizations:           u.allowedOrganizations,
		AuthorizationURL:               u.authorizationURL,
		GetUserFunc: func(ctx context.Context, accessToken string) (*upstreamprovider.GitHubUser, error) {
			if u.getUserErr != nil {
				return nil, u.getUserErr
			}
			return u.getUserUser, nil
		},
		ExchangeAuthcodeFunc: func(ctx context.Context, authcode string) (string, error) {
			if u.authcodeExchangeErr != nil {
				return "", u.authcodeExchangeErr
			}
			return u.accessToken, nil
		},
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
	GetUserFunc                    func(ctx context.Context, accessToken string) (*upstreamprovider.GitHubUser, error)
	ExchangeAuthcodeFunc           func(ctx context.Context, authcode string) (string, error)

	// Fields for tracking actual calls make to mock functions.
	exchangeAuthcodeCallCount int
	exchangeAuthcodeArgs      []*ExchangeAuthcodeArgs
	getUserCallCount          int
	getUserArgs               []*GetUserArgs
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

func (u *TestUpstreamGitHubIdentityProvider) ExchangeAuthcode(
	ctx context.Context,
	authcode string,
	redirectURI string,
) (string, error) {
	if u.exchangeAuthcodeArgs == nil {
		u.exchangeAuthcodeArgs = make([]*ExchangeAuthcodeArgs, 0)
	}
	u.exchangeAuthcodeCallCount++
	u.exchangeAuthcodeArgs = append(u.exchangeAuthcodeArgs, &ExchangeAuthcodeArgs{
		Ctx:         ctx,
		Authcode:    authcode,
		RedirectURI: redirectURI,
	})
	return u.ExchangeAuthcodeFunc(ctx, authcode)
}

func (u *TestUpstreamGitHubIdentityProvider) ExchangeAuthcodeCallCount() int {
	return u.exchangeAuthcodeCallCount
}

func (u *TestUpstreamGitHubIdentityProvider) ExchangeAuthcodeArgs(call int) *ExchangeAuthcodeArgs {
	if u.exchangeAuthcodeArgs == nil {
		u.exchangeAuthcodeArgs = make([]*ExchangeAuthcodeArgs, 0)
	}
	return u.exchangeAuthcodeArgs[call]
}

func (u *TestUpstreamGitHubIdentityProvider) GetUser(ctx context.Context, accessToken string) (*upstreamprovider.GitHubUser, error) {
	if u.getUserArgs == nil {
		u.getUserArgs = make([]*GetUserArgs, 0)
	}
	u.getUserCallCount++
	u.getUserArgs = append(u.getUserArgs, &GetUserArgs{
		Ctx:         ctx,
		AccessToken: accessToken,
	})
	return u.GetUserFunc(ctx, accessToken)
}

func (u *TestUpstreamGitHubIdentityProvider) GetUserCallCount() int {
	return u.getUserCallCount
}

func (u *TestUpstreamGitHubIdentityProvider) GetUserArgs(call int) *GetUserArgs {
	if u.getUserArgs == nil {
		u.getUserArgs = make([]*GetUserArgs, 0)
	}
	return u.getUserArgs[call]
}
