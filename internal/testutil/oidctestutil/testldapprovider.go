// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"net/url"

	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
)

func NewTestUpstreamLDAPIdentityProviderBuilder() *TestUpstreamLDAPIdentityProviderBuilder {
	return &TestUpstreamLDAPIdentityProviderBuilder{}
}

type TestUpstreamLDAPIdentityProviderBuilder struct {
	name                           string
	resourceUID                    types.UID
	url                            *url.URL
	authenticateFunc               func(ctx context.Context, username, password string) (*authenticators.Response, bool, error)
	performRefreshErr              error
	performRefreshGroups           []string
	displayNameForFederationDomain string
	transformsForFederationDomain  *idtransform.TransformationPipeline
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithName(name string) *TestUpstreamLDAPIdentityProviderBuilder {
	t.name = name
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithResourceUID(uid types.UID) *TestUpstreamLDAPIdentityProviderBuilder {
	t.resourceUID = uid
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithURL(url *url.URL) *TestUpstreamLDAPIdentityProviderBuilder {
	t.url = url
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithAuthenticateFunc(f func(ctx context.Context, username, password string) (*authenticators.Response, bool, error)) *TestUpstreamLDAPIdentityProviderBuilder {
	t.authenticateFunc = f
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithPerformRefreshErr(err error) *TestUpstreamLDAPIdentityProviderBuilder {
	t.performRefreshErr = err
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithPerformRefreshGroups(groups []string) *TestUpstreamLDAPIdentityProviderBuilder {
	t.performRefreshGroups = groups
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithDisplayNameForFederationDomain(displayName string) *TestUpstreamLDAPIdentityProviderBuilder {
	t.displayNameForFederationDomain = displayName
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) WithTransformsForFederationDomain(transforms *idtransform.TransformationPipeline) *TestUpstreamLDAPIdentityProviderBuilder {
	t.transformsForFederationDomain = transforms
	return t
}

func (t *TestUpstreamLDAPIdentityProviderBuilder) Build() *TestUpstreamLDAPIdentityProvider {
	if t.displayNameForFederationDomain == "" {
		// default it to the CR name
		t.displayNameForFederationDomain = t.name
	}
	if t.transformsForFederationDomain == nil {
		// default to an empty pipeline
		t.transformsForFederationDomain = idtransform.NewTransformationPipeline()
	}
	return &TestUpstreamLDAPIdentityProvider{
		Name:                           t.name,
		ResourceUID:                    t.resourceUID,
		URL:                            t.url,
		AuthenticateFunc:               t.authenticateFunc,
		PerformRefreshErr:              t.performRefreshErr,
		PerformRefreshGroups:           t.performRefreshGroups,
		DisplayNameForFederationDomain: t.displayNameForFederationDomain,
		TransformsForFederationDomain:  t.transformsForFederationDomain,
	}
}

type TestUpstreamLDAPIdentityProvider struct {
	Name                           string
	ResourceUID                    types.UID
	URL                            *url.URL
	AuthenticateFunc               func(ctx context.Context, username, password string) (*authenticators.Response, bool, error)
	PerformRefreshErr              error
	PerformRefreshGroups           []string
	DisplayNameForFederationDomain string
	TransformsForFederationDomain  *idtransform.TransformationPipeline

	// Fields for tracking actual calls make to mock functions.
	performRefreshCallCount int
	performRefreshArgs      []*PerformRefreshArgs
}

var _ upstreamprovider.UpstreamLDAPIdentityProviderI = &TestUpstreamLDAPIdentityProvider{}

func (u *TestUpstreamLDAPIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamLDAPIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamLDAPIdentityProvider) AuthenticateUser(ctx context.Context, username, password string) (*authenticators.Response, bool, error) {
	return u.AuthenticateFunc(ctx, username, password)
}

func (u *TestUpstreamLDAPIdentityProvider) GetURL() *url.URL {
	return u.URL
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefresh(ctx context.Context, storedRefreshAttributes upstreamprovider.RefreshAttributes, _idpDisplayName string) ([]string, error) {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	u.performRefreshCallCount++
	u.performRefreshArgs = append(u.performRefreshArgs, &PerformRefreshArgs{
		Ctx:              ctx,
		DN:               storedRefreshAttributes.DN,
		ExpectedUsername: storedRefreshAttributes.Username,
		ExpectedSubject:  storedRefreshAttributes.Subject,
	})
	if u.PerformRefreshErr != nil {
		return nil, u.PerformRefreshErr
	}
	return u.PerformRefreshGroups, nil
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefreshCallCount() int {
	return u.performRefreshCallCount
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefreshArgs(call int) *PerformRefreshArgs {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	return u.performRefreshArgs[call]
}
