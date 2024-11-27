// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auditevent

type Message string

const (
	// Supervisor request logging.

	HTTPRequestReceived          Message = "HTTP Request Received"
	HTTPRequestCompleted         Message = "HTTP Request Completed"
	HTTPRequestParameters        Message = "HTTP Request Parameters"
	HTTPRequestCustomHeadersUsed Message = "HTTP Request Custom Headers Used"
	HTTPRequestBasicAuthUsed     Message = "HTTP Request Basic Auth"

	// Supervisor authentication logging.

	UsingUpstreamIDP                   Message = "Using Upstream IDP"
	AuthorizeIDFromParameters          Message = "AuthorizeID From Parameters"
	IdentityFromUpstreamIDP            Message = "Identity From Upstream IDP"
	UpstreamAuthorizeRedirect          Message = "Upstream Authorize Redirect"
	IdentityRefreshedFromUpstreamIDP   Message = "Identity Refreshed From Upstream IDP"
	IDTokenIssued                      Message = "ID Token Issued" //nolint:gosec // this is not a credential
	SessionStarted                     Message = "Session Started"
	SessionRefreshed                   Message = "Session Refreshed"
	SessionFound                       Message = "Session Found"
	AuthenticationRejectedByTransforms Message = "Authentication Rejected By Transforms"
	IncorrectUsernameOrPassword        Message = "Incorrect Username Or Password"

	// Supervisor session ending logging.

	UpstreamOIDCTokenRevoked Message = "Upstream OIDC Token Revoked" //nolint:gosec // this is not a credential
	SessionGarbageCollected  Message = "Session Garbage Collected"

	// Supervisor aggregated APIs logging.

	OIDCClientSecretRequestUpdatedSecrets Message = "OIDCClientSecretRequest Updated Secrets"

	// Concierge aggregated APIs logging.

	TokenCredentialRequestTokenReceived        Message = "TokenCredentialRequest Token Received"        //nolint:gosec // this is not a credential
	TokenCredentialRequestAuthenticatedUser    Message = "TokenCredentialRequest Authenticated User"    //nolint:gosec // this is not a credential
	TokenCredentialRequestAuthenticationFailed Message = "TokenCredentialRequest Authentication Failed" //nolint:gosec // this is not a credential
	TokenCredentialRequestUnexpectedError      Message = "TokenCredentialRequest Unexpected Error"      //nolint:gosec // this is not a credential
	TokenCredentialRequestUnsupportedUserInfo  Message = "TokenCredentialRequest Unsupported UserInfo"  //nolint:gosec // this is not a credential
)
