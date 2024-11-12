// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downstreamsession provides some shared helpers for creating downstream OIDC sessions.
package downstreamsession

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/auditevent"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

const idTransformUnexpectedErr = constable.Error("configured identity transformation or policy resulted in unexpected error")

// SessionConfig is everything that is needed to start a new downstream Pinniped session, including the upstream and
// downstream identities of the user. All fields are required.
type SessionConfig struct {
	UpstreamIdentity    *resolvedprovider.Identity
	UpstreamLoginExtras *resolvedprovider.IdentityLoginExtras
	// The ID of the client who started the new downstream session.
	ClientID string
	// The scopes that were granted for the new downstream session.
	GrantedScopes []string
	// The identity provider used to authenticate the user.
	IdentityProvider resolvedprovider.FederationDomainResolvedIdentityProvider
	// The fosite Requester that is starting this session.
	SessionIDGetter plog.SessionIDGetter
}

// NewPinnipedSession applies the configured FederationDomain identity transformations
// and creates a downstream Pinniped session.
func NewPinnipedSession(
	ctx context.Context,
	auditLogger plog.AuditLogger,
	c *SessionConfig,
) (*psession.PinnipedSession, error) {
	now := time.Now().UTC()

	auditLogger.Audit(auditevent.IdentityFromUpstreamIDP, &plog.AuditParams{
		ReqCtx: ctx,
		KeysAndValues: []any{
			"upstreamIDPDisplayName", c.IdentityProvider.GetDisplayName(),
			"upstreamIDPType", c.IdentityProvider.GetSessionProviderType(),
			"upstreamIDPResourceName", c.IdentityProvider.GetProvider().GetResourceName(),
			"upstreamIDPResourceUID", c.IdentityProvider.GetProvider().GetResourceUID(),
			"upstreamUsername", c.UpstreamIdentity.UpstreamUsername,
			"upstreamGroups", c.UpstreamIdentity.UpstreamGroups,
		},
	})

	downstreamUsername, downstreamGroups, err := applyIdentityTransformations(ctx,
		c.IdentityProvider.GetTransforms(), c.UpstreamIdentity.UpstreamUsername, c.UpstreamIdentity.UpstreamGroups)
	if err != nil {
		auditLogger.Audit(auditevent.AuthenticationRejectedByTransforms, &plog.AuditParams{
			ReqCtx:        ctx,
			KeysAndValues: []any{"reason", err},
		})
		return nil, err
	}

	customSessionData := &psession.CustomSessionData{
		Username:         downstreamUsername,
		UpstreamUsername: c.UpstreamIdentity.UpstreamUsername,
		UpstreamGroups:   c.UpstreamIdentity.UpstreamGroups,
		ProviderUID:      c.IdentityProvider.GetProvider().GetResourceUID(),
		ProviderName:     c.IdentityProvider.GetProvider().GetResourceName(),
		ProviderType:     c.IdentityProvider.GetSessionProviderType(),
		Warnings:         c.UpstreamLoginExtras.Warnings,
	}
	c.IdentityProvider.ApplyIDPSpecificSessionDataToSession(customSessionData, c.UpstreamIdentity.IDPSpecificSessionData)

	pinnipedSession := &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims: &fositejwt.IDTokenClaims{
				Subject:     c.UpstreamIdentity.DownstreamSubject,
				RequestedAt: now,
				AuthTime:    now,
			},
		},
		Custom: customSessionData,
	}

	extras := map[string]any{}

	extras[oidcapi.IDTokenClaimAuthorizedParty] = c.ClientID

	if slices.Contains(c.GrantedScopes, oidcapi.ScopeUsername) {
		extras[oidcapi.IDTokenClaimUsername] = downstreamUsername
	}

	if slices.Contains(c.GrantedScopes, oidcapi.ScopeGroups) {
		if downstreamGroups == nil {
			downstreamGroups = []string{}
		}
		extras[oidcapi.IDTokenClaimGroups] = downstreamGroups
	}

	if len(c.UpstreamLoginExtras.DownstreamAdditionalClaims) > 0 {
		extras[oidcapi.IDTokenClaimAdditionalClaims] = c.UpstreamLoginExtras.DownstreamAdditionalClaims
	}

	pinnipedSession.IDTokenClaims().Extra = extras

	auditLogger.Audit(auditevent.SessionStarted, &plog.AuditParams{
		ReqCtx:  ctx,
		Session: c.SessionIDGetter,
		KeysAndValues: []any{
			"username", downstreamUsername,
			"groups", downstreamGroups,
			"subject", c.UpstreamIdentity.DownstreamSubject,
			"additionalClaims", c.UpstreamLoginExtras.DownstreamAdditionalClaims,
			"warnings", c.UpstreamLoginExtras.Warnings,
		},
	})

	return pinnipedSession, nil
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

// applyIdentityTransformations applies an identity transformation pipeline to an upstream identity to transform
// or potentially reject the identity.
func applyIdentityTransformations(
	ctx context.Context,
	transforms *idtransform.TransformationPipeline,
	username string,
	groups []string,
) (string, []string, error) {
	transformationResult, err := transforms.Evaluate(ctx, username, groups)
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
