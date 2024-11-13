// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auditevent

import (
	"net/url"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Message string

const (
	HTTPRequestReceived                        Message = "HTTP Request Received"
	HTTPRequestCompleted                       Message = "HTTP Request Completed"
	HTTPRequestParameters                      Message = "HTTP Request Parameters"
	HTTPRequestCustomHeadersUsed               Message = "HTTP Request Custom Headers Used"
	UsingUpstreamIDP                           Message = "Using Upstream IDP"
	AuthorizeIDFromParameters                  Message = "AuthorizeID From Parameters"
	IdentityFromUpstreamIDP                    Message = "Identity From Upstream IDP"
	IdentityRefreshedFromUpstreamIDP           Message = "Identity Refreshed From Upstream IDP"
	SessionStarted                             Message = "Session Started"
	SessionRefreshed                           Message = "Session Refreshed"
	AuthenticationRejectedByTransforms         Message = "Authentication Rejected By Transforms"
	UpstreamOIDCTokenRevoked                   Message = "Upstream OIDC Token Revoked" //nolint:gosec // this is not a credential
	SessionGarbageCollected                    Message = "Session Garbage Collected"
	UpstreamAuthorizeRedirect                  Message = "Upstream Authorize Redirect"
	TokenCredentialRequestAuthenticatedUser    Message = "TokenCredentialRequest Authenticated User"    //nolint:gosec // this is not a credential
	TokenCredentialRequestAuthenticationFailed Message = "TokenCredentialRequest Authentication Failed" //nolint:gosec // this is not a credential
	TokenCredentialRequestUnexpectedError      Message = "TokenCredentialRequest Unexpected Error"      //nolint:gosec // this is not a credential
	TokenCredentialRequestUnsupportedUserInfo  Message = "TokenCredentialRequest Unsupported UserInfo"  //nolint:gosec // this is not a credential
)

// SanitizeParams can be used to redact all params not included in the allowedKeys set.
// Useful when audit logging HTTPRequestParameters events.
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
