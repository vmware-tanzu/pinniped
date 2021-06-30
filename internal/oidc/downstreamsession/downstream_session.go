// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downstreamsession provides some shared helpers for creating downstream OIDC sessions.
package downstreamsession

import (
	"time"

	oidc2 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"go.pinniped.dev/internal/oidc"
)

// MakeDownstreamSession creates a downstream OIDC session.
func MakeDownstreamSession(subject string, username string, groups []string) *openid.DefaultSession {
	now := time.Now().UTC()
	openIDSession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     subject,
			RequestedAt: now,
			AuthTime:    now,
		},
	}
	if groups == nil {
		groups = []string{}
	}
	openIDSession.Claims.Extra = map[string]interface{}{
		oidc.DownstreamUsernameClaim: username,
		oidc.DownstreamGroupsClaim:   groups,
	}
	return openIDSession
}

// GrantScopesIfRequested auto-grants the scopes for which we do not require end-user approval, if they were requested.
func GrantScopesIfRequested(authorizeRequester fosite.AuthorizeRequester) {
	oidc.GrantScopeIfRequested(authorizeRequester, oidc2.ScopeOpenID)
	oidc.GrantScopeIfRequested(authorizeRequester, oidc2.ScopeOfflineAccess)
	oidc.GrantScopeIfRequested(authorizeRequester, "pinniped:request-audience")
}
