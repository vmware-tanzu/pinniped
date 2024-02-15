// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downstreamsession provides some shared helpers for creating downstream OIDC sessions.
package downstreamsession

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"k8s.io/utils/strings/slices"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

const idTransformUnexpectedErr = constable.Error("configured identity transformation or policy resulted in unexpected error")

// MakeDownstreamSession creates a downstream OIDC session.
func MakeDownstreamSession(identity *resolvedprovider.Identity, grantedScopes []string, clientID string) *psession.PinnipedSession {
	now := time.Now().UTC()
	openIDSession := &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:     identity.Subject,
				RequestedAt: now,
				AuthTime:    now,
			},
		},
		Custom: identity.SessionData,
	}

	extras := map[string]interface{}{}
	extras[oidcapi.IDTokenClaimAuthorizedParty] = clientID
	if slices.Contains(grantedScopes, oidcapi.ScopeUsername) {
		extras[oidcapi.IDTokenClaimUsername] = identity.SessionData.Username
	}
	if slices.Contains(grantedScopes, oidcapi.ScopeGroups) {
		groups := identity.Groups
		if groups == nil {
			groups = []string{}
		}
		extras[oidcapi.IDTokenClaimGroups] = groups
	}
	if len(identity.AdditionalClaims) > 0 {
		extras[oidcapi.IDTokenClaimAdditionalClaims] = identity.AdditionalClaims
	}
	openIDSession.IDTokenClaims().Extra = extras

	return openIDSession
}

// AutoApproveScopes auto-grants the scopes which we support and for which we do not require end-user approval,
// if they were requested. This should only be called after it has been validated that the client is allowed to request
// the scopes that it requested (which is a check performed by fosite).
func AutoApproveScopes(authorizeRequester fosite.AuthorizeRequester) {
	for _, scope := range []string{
		oidcapi.ScopeOpenID,
		oidcapi.ScopeOfflineAccess,
		oidcapi.ScopeRequestAudience,
		oidcapi.ScopeUsername,
		oidcapi.ScopeGroups,
	} {
		oidc.GrantScopeIfRequested(authorizeRequester, scope)
	}

	// For backwards-compatibility with old pinniped CLI binaries which never request the username and groups scopes
	// (because those scopes did not exist yet when those CLIs were released), grant/approve the username and groups
	// scopes even if the CLI did not request them. Basically, pretend that the CLI requested them and auto-approve
	// them. Newer versions of the CLI binaries will request these scopes, so after enough time has passed that
	// we can assume the old versions of the CLI are no longer in use in the wild, then we can remove this code and
	// just let the above logic handle all clients.
	if authorizeRequester.GetClient().GetID() == oidcapi.ClientIDPinnipedCLI {
		authorizeRequester.GrantScope(oidcapi.ScopeUsername)
		authorizeRequester.GrantScope(oidcapi.ScopeGroups)
	}
}

// ApplyIdentityTransformations applies an identity transformation pipeline to an upstream identity to transform
// or potentially reject the identity.
func ApplyIdentityTransformations(
	ctx context.Context,
	identityTransforms *idtransform.TransformationPipeline,
	username string,
	groups []string,
) (string, []string, error) {
	transformationResult, err := identityTransforms.Evaluate(ctx, username, groups)
	if err != nil {
		plog.Error("unexpected identity transformation error during authentication", err, "inputUsername", username)
		return "", nil, idTransformUnexpectedErr
	}
	if !transformationResult.AuthenticationAllowed {
		plog.Debug("authentication rejected by configured policy", "inputUsername", username, "inputGroups", groups)
		return "", nil, fmt.Errorf("configured identity policy rejected this authentication: %s", transformationResult.RejectedAuthenticationMessage)
	}
	plog.Debug("identity transformation successfully applied during authentication",
		"originalUsername", username,
		"newUsername", transformationResult.Username,
		"originalGroups", groups,
		"newGroups", transformationResult.Groups,
	)
	return transformationResult.Username, transformationResult.Groups, nil
}
