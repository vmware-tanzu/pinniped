// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedprovider

import (
	"context"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

type Identity struct {
	// Note that the username is stored in SessionData.Username.
	SessionData      *psession.CustomSessionData
	Groups           []string
	Subject          string
	AdditionalClaims map[string]interface{}
}

type UpstreamAuthorizeRequestState struct {
	EncodedStateParam string
	PKCE              pkce.Code
	Nonce             nonce.Nonce
}

type FederationDomainResolvedIdentityProvider interface {
	GetDisplayName() string

	GetProvider() upstreamprovider.UpstreamIdentityProviderI

	GetSessionProviderType() psession.ProviderType

	GetIDPDiscoveryType() v1alpha1.IDPType

	GetIDPDiscoveryFlows() []v1alpha1.IDPFlow

	GetTransforms() *idtransform.TransformationPipeline

	// UpstreamAuthorizeRedirectURL returns the URL to which the user's browser can be redirected to continue
	// the downstream browser-based authorization flow. Returned errors should be of type fosite.RFC6749Error.
	UpstreamAuthorizeRedirectURL(state *UpstreamAuthorizeRequestState, downstreamIssuerURL string) (string, error)

	// Login performs auth using a username and password that was submitted by the client, without a web browser.
	// This function should authenticate the user with the upstream identity provider, extract their upstream
	// identity, and transform it into their downstream identity.
	// The groupsWillBeIgnored parameter will be true when the returned groups are going to be ignored by the caller,
	// in which case this function may be able to save some effort by avoiding getting the user's upstream groups.
	// Returned errors should be of type fosite.RFC6749Error.
	Login(ctx context.Context, submittedUsername string, submittedPassword string, groupsWillBeIgnored bool) (*Identity, error)

	// HandleCallback handles an OAuth-style callback in a browser-based flow. This function should complete
	// the authorization with the upstream identity provider using the authCode, extract their upstream
	// identity, and transform it into their downstream identity.
	// Returned errors should be from the httperr package.
	HandleCallback(ctx context.Context, authCode string, pkce pkce.Code, nonce nonce.Nonce, redirectURI string) (*Identity, error)
}
