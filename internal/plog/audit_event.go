// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"net/url"

	"k8s.io/apimachinery/pkg/util/sets"
)

type AuditEventMessage string

const (
	AuditEventHTTPRequestReceived                AuditEventMessage = "HTTP Request Received"
	AuditEventHTTPRequestCompleted               AuditEventMessage = "HTTP Request Completed"
	AuditEventHTTPRequestParameters              AuditEventMessage = "HTTP Request Parameters"
	AuditEventHTTPRequestCustomHeadersUsed       AuditEventMessage = "HTTP Request Custom Headers Used"
	AuditEventUsingUpstreamIDP                   AuditEventMessage = "Using Upstream IDP"
	AuditEventAuthorizeIDFromParameters          AuditEventMessage = "AuthorizeID From Parameters"
	AuditEventIdentityFromUpstreamIDP            AuditEventMessage = "Identity From Upstream IDP"
	AuditEventIdentityRefreshedFromUpstreamIDP   AuditEventMessage = "Identity Refreshed From Upstream IDP"
	AuditEventSessionStarted                     AuditEventMessage = "Session Started"
	AuditEventSessionRefreshed                   AuditEventMessage = "Session Refreshed"
	AuditEventAuthenticationRejectedByTransforms AuditEventMessage = "Authentication Rejected By Transforms"
	AuditEventUpstreamOIDCTokenRevoked           AuditEventMessage = "Upstream OIDC Token Revoked" //nolint:gosec // this is not a credential
	AuditEventSessionGarbageCollected            AuditEventMessage = "Session Garbage Collected"
	AuditEventTokenCredentialRequest             AuditEventMessage = "TokenCredentialRequest" //nolint:gosec // this is not a credential
	AuditEventUpstreamAuthorizeRedirect          AuditEventMessage = "Upstream Authorize Redirect"
)

// SanitizeParams can be used to redact all params not included in the allowedKeys set.
// Useful when audit logging AuditEventHTTPRequestParameters events.
func SanitizeParams(params url.Values, allowedKeys sets.Set[string]) string {
	if len(params) == 0 {
		return ""
	}
	sanitized := url.Values{}
	for key := range params {
		if allowedKeys.Has(key) {
			sanitized[key] = params[key]
		} else {
			for range params[key] {
				sanitized.Add(key, "redacted")
			}
		}
	}
	return sanitized.Encode()
}
