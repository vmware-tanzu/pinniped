// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedprovider

import (
	"context"
	"errors"
	"net/http"

	"github.com/ory/fosite"

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

	// UpstreamRefresh performs a refresh with the upstream provider.
	// The user's session information is passed in, and implementations should be careful mutating anything about the
	// session because changes will be saved into the session.
	// If possible, implementations should update the user's group memberships by fetching them from the
	// upstream provider during the refresh, and returning them.
	// The groupsWillBeIgnored parameter will be true when the returned groups are going to be ignored by the caller,
	// in which case this function may be able to save some effort by avoiding getting the user's upstream groups.
	// Returned errors should be of type fosite.RFC6749Error.
	UpstreamRefresh(ctx context.Context, session *psession.PinnipedSession, groupsWillBeIgnored bool) (refreshedGroups []string, err error)
}

func ErrMissingUpstreamSessionInternalError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "There was an internal server error.",
		HintField:        "Required upstream data not found in session.",
		CodeField:        http.StatusInternalServerError,
	}
}

func ErrUpstreamRefreshError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "Error during upstream refresh.",
		CodeField:        http.StatusUnauthorized,
	}
}

func TransformRefreshedIdentity(
	ctx context.Context,
	transforms *idtransform.TransformationPipeline,
	oldTransformedUsername string,
	upstreamUsername string,
	upstreamGroups []string,
	providerName string,
	providerType psession.ProviderType,
) (*idtransform.TransformationResult, error) {
	transformationResult, err := transforms.Evaluate(ctx, upstreamUsername, upstreamGroups)
	if err != nil {
		return nil, ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh error while applying configured identity transformations.").
			WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if !transformationResult.AuthenticationAllowed {
		return nil, ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh rejected by configured identity policy: %s.", transformationResult.RejectedAuthenticationMessage).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if oldTransformedUsername != transformationResult.Username {
		return nil, ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").
			WithTrace(errors.New("username in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	return transformationResult, nil
}
