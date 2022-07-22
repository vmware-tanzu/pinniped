// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
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

	// AuthorizeUpstreamIDPNameParamName is the name of the HTTP request parameter which can be used to help select which
	// identity provider should be used for authentication by sending the name of the desired identity provider.
	AuthorizeUpstreamIDPNameParamName = "pinniped_idp_name"

	// AuthorizeUpstreamIDPTypeParamName is the name of the HTTP request parameter which can be used to help select which
	// identity provider should be used for authentication by sending the type of the desired identity provider.
	AuthorizeUpstreamIDPTypeParamName = "pinniped_idp_type"
)
