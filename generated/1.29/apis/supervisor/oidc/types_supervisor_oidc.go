// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

// Constants related to the Supervisor FederationDomain's authorization and token endpoints.
const (
	// AuthorizeUsernameHeaderName is the name of the HTTP header which can be used to transmit a username
	// to the authorize endpoint when using a password flow, for example an OIDCIdentityProvider with a password grant
	// or an LDAPIdentityProvider.
	AuthorizeUsernameHeaderName = "Pinniped-Username"

	// AuthorizePasswordHeaderName is the name of the HTTP header which can be used to transmit a password
	// to the authorize endpoint when using a password flow, for example an OIDCIdentityProvider with a password grant
	// or an LDAPIdentityProvider.
	AuthorizePasswordHeaderName = "Pinniped-Password" //nolint:gosec // this is not a credential

	// AuthorizeUpstreamIDPNameParamName is the name of the HTTP request parameter which can be used to help select
	// which identity provider should be used for authentication by sending the name of the desired identity provider.
	AuthorizeUpstreamIDPNameParamName = "pinniped_idp_name"

	// AuthorizeUpstreamIDPTypeParamName is the name of the HTTP request parameter which can be used to help select
	// which identity provider should be used for authentication by sending the type of the desired identity provider.
	AuthorizeUpstreamIDPTypeParamName = "pinniped_idp_type"

	// IDTokenClaimIssuer is name of the issuer claim defined by the OIDC spec.
	IDTokenClaimIssuer = "iss"

	// IDTokenClaimSubject is name of the subject claim defined by the OIDC spec.
	IDTokenClaimSubject = "sub"

	// IDTokenSubClaimIDPNameQueryParam is the name of the query param used in the values of the "sub" claim
	// in Supervisor-issued ID tokens to identify with which external identity provider the user authenticated.
	IDTokenSubClaimIDPNameQueryParam = "idpName"

	// IDTokenClaimAuthorizedParty is name of the authorized party claim defined by the OIDC spec.
	IDTokenClaimAuthorizedParty = "azp"

	// IDTokenClaimUsername is the name of a custom claim in the downstream ID token whose value will contain the user's
	// username which was mapped from the upstream identity provider.
	IDTokenClaimUsername = "username"

	// IDTokenClaimGroups is the name of a custom claim in the downstream ID token whose value will contain the user's
	// group names which were mapped from the upstream identity provider.
	IDTokenClaimGroups = "groups"

	// IDTokenClaimAdditionalClaims is the top level claim used to hold additional claims in the downstream ID
	// token, if any claims are present.
	IDTokenClaimAdditionalClaims = "additionalClaims"

	// GrantTypeAuthorizationCode is the name of the grant type for authorization code flows defined by the OIDC spec.
	GrantTypeAuthorizationCode = "authorization_code"

	// GrantTypeRefreshToken is the name of the grant type for refresh flow defined by the OIDC spec.
	GrantTypeRefreshToken = "refresh_token"

	// GrantTypeTokenExchange is the name of a custom grant type for RFC8693 token exchanges.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // this is not a credential

	// ScopeOpenID is name of the openid scope defined by the OIDC spec.
	ScopeOpenID = "openid"

	// ScopeOfflineAccess is name of the offline access scope defined by the OIDC spec, used for requesting refresh
	// tokens.
	ScopeOfflineAccess = "offline_access"

	// ScopeEmail is name of the email scope defined by the OIDC spec.
	ScopeEmail = "email"

	// ScopeProfile is name of the profile scope defined by the OIDC spec.
	ScopeProfile = "profile"

	// ScopeUsername is the name of a custom scope that determines whether the username claim will be returned inside
	// ID tokens.
	ScopeUsername = "username"

	// ScopeGroups is the name of a custom scope that determines whether the groups claim will be returned inside
	// ID tokens.
	ScopeGroups = "groups"

	// ScopeRequestAudience is the name of a custom scope that determines whether a RFC8693 token exchange is allowed to
	// be used to request a different audience.
	ScopeRequestAudience = "pinniped:request-audience"

	// ClientIDPinnipedCLI is the client ID of the statically defined public OIDC client which is used by the CLI.
	ClientIDPinnipedCLI = "pinniped-cli"

	// ClientIDRequiredOIDCClientPrefix is the required prefix for the metadata.name of OIDCClient CRs.
	ClientIDRequiredOIDCClientPrefix = "client.oauth.pinniped.dev-"
)
