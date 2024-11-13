// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auditevent

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
	IncorrectUsernameOrPassword                Message = "Incorrect Username Or Password"               //nolint:gosec // this is not a credential
)
