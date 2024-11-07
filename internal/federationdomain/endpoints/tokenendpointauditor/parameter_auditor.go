// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokenendpointauditor

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/plog"
)

type parameterAuditorHandler struct {
	auditLogger plog.AuditLogger
}

func AuditorHandlerFactory(auditLogger plog.AuditLogger) compose.Factory {
	return func(_ fosite.Configurator, _ any, _ any) any {
		return &parameterAuditorHandler{
			auditLogger: auditLogger,
		}
	}
}

var _ fosite.TokenEndpointHandler = (*parameterAuditorHandler)(nil)

func (p parameterAuditorHandler) PopulateTokenEndpointResponse(_ context.Context, _ fosite.AccessRequester, _ fosite.AccessResponder) error {
	return nil
}

func (p parameterAuditorHandler) HandleTokenEndpointRequest(_ context.Context, _ fosite.AccessRequester) error {
	return nil
}

func (p parameterAuditorHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

func paramsSafeToLogTokenEndpoint() sets.Set[string] {
	return sets.New(
		// Standard params from https://openid.net/specs/openid-connect-core-1_0.html for authcode and refresh grants.
		// Redacting code, client_secret, refresh_token, and PKCE code_verifier params.
		"grant_type", "client_id", "redirect_uri", "scope",
		// Token exchange params from https://datatracker.ietf.org/doc/html/rfc8693.
		// Redact subject_token and actor_token.
		// We don't allow all of these, but they should be safe to log.
		"audience", "resource", "scope", "requested_token_type", "actor_token_type", "subject_token_type",
	)
}

func (p parameterAuditorHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	p.auditLogger.Audit(plog.AuditEventHTTPRequestParameters, ctx, plog.NoSessionPersisted(),
		plog.SanitizeParams(requester.GetRequestForm(), paramsSafeToLogTokenEndpoint())...)

	return false
}
