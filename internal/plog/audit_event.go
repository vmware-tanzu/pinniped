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
func SanitizeParams(inputParams url.Values, allowedKeys sets.Set[string]) []any {
	params := make(map[string]string)
	multiValueParams := make(url.Values)

	transform := func(key, value string) string {
		if !allowedKeys.Has(key) {
			return "redacted"
		}

		unescape, err := url.QueryUnescape(value)
		if err != nil {
			// ignore these errors and just use the original query parameter
			unescape = value
		}
		return unescape
	}

	for key := range inputParams {
		for i, p := range inputParams[key] {
			transformed := transform(key, p)
			if i == 0 {
				params[key] = transformed
			}

			if len(inputParams[key]) > 1 {
				multiValueParams[key] = append(multiValueParams[key], transformed)
			}
		}
	}

	if len(multiValueParams) > 0 {
		return []any{"params", params, "multiValueParams", multiValueParams}

	}
	return []any{"params", params}
}
