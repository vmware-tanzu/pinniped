// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedprovider

import (
	"context"
	"net/http"

	"github.com/ory/fosite"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// Identity is the information that an identity provider must determine from the upstream IDP during login.
// This information will also be passed back to the identity provider interface during a refresh flow to
// represent the user's previous identity from their original login or most recent refresh, to aid in
// validating the refresh.
type Identity struct {
	// The username extracted from the upstream identity provider, before identity
	// transformations are applied to determine the final downstream username.
	// Must not be empty.
	UpstreamUsername string

	// The group names extracted from the upstream identity provider, before identity transformations
	// are applied to determine the final downstream group names. nil or an empty list means that the
	// user belongs to no upstream groups (before applying identity transformations to determine their
	// downstream group memberships).
	UpstreamGroups []string

	// The downstream subject determined for this user in an identity provider-specific way.
	// Must not be empty.
	DownstreamSubject string

	// The portion of the user's session data which is specific to the upstream identity provider type.
	// Refer to the fields of psession.CustomSessionData whose types are specific to an identity provider type.
	// Must not be nil.
	IDPSpecificSessionData any
}

// IdentityLoginExtras are additional information that an identity provider may choose to determine
// during login. This information will not be passed into the
// FederationDomainResolvedIdentityProvider.UpstreamRefresh function, so it does not impact upstream
// refreshes. Its fields are optional and may be nil.
type IdentityLoginExtras struct {
	// The downstream additional claims determined for this user in an identity provider-specific way, if any.
	DownstreamAdditionalClaims map[string]any

	// Login warnings to show the user after they exchange their downstream authcode, if any.
	Warnings []string
}

// RefreshedIdentity represents the parts of an identity that an identity provider may update
// from the upstream IDP during a refresh. It will be returned when performing an upstream refresh.
type RefreshedIdentity struct {
	// The username extracted from the upstream identity provider, before identity
	// transformations are applied to determine the final downstream username.
	// Must not be empty.
	UpstreamUsername string

	// The group names extracted from the upstream identity provider, before identity
	// transformations are applied to determine the final downstream group names.
	// If refreshing the groups was not possible, then set this to nil, and the user's old groups
	// from their session will be used again. Returning an empty list of groups will mean
	// that the user's upstream group membership will be updated to make them belong to no
	// upstream groups (before applying identity transformations to determine their downstream
	// group memberships).
	UpstreamGroups []string

	// The portion of the user's session data which is specific to the upstream identity provider type.
	// Refer to the fields of psession.CustomSessionData whose types are specific to an identity provider type.
	// Set this to be the potentially updated IDP-specific session data. If no updates were required, then
	// set this to nil.
	IDPSpecificSessionData any
}

// UpstreamAuthorizeRequestState is the state capturing the downstream authorization request, used as a parameter to
// FederationDomainResolvedIdentityProvider.UpstreamAuthorizeRedirectURL to help formulate the upstream authorization
// request. It includes the state param that should be sent in the upstream authorization request. It also includes
// the information needed to create the PKCE and nonce parameters for the upstream authorization request. If the
// upstream authorization request does not allow PKCE, then implementations of
// FederationDomainResolvedIdentityProvider.UpstreamAuthorizeRedirectURL may choose to ignore that struct field.
type UpstreamAuthorizeRequestState struct {
	EncodedStateParam stateparam.Encoded
	PKCE              pkce.Code
	Nonce             nonce.Nonce
}

type FederationDomainResolvedIdentityProvider interface {
	// GetDisplayName returns the display name of this identity provider, as configured in the FederationDomain.
	GetDisplayName() string

	// GetProvider returns a representation of the upstream identity provider custom resource related to this
	// identity provider for the FederationDomain, e.g. the OIDCIdentityProvider.
	GetProvider() upstreamprovider.UpstreamIdentityProviderI

	// GetSessionProviderType returns the type of session created by this identity provider.
	GetSessionProviderType() psession.ProviderType

	// GetIDPDiscoveryType returns the type of this identity provider, as shown by the IDP discovery endpoint.
	GetIDPDiscoveryType() v1alpha1.IDPType

	// GetIDPDiscoveryFlows returns the supported flows of this identity provider,
	// as shown by the IDP discovery endpoint.
	GetIDPDiscoveryFlows() []v1alpha1.IDPFlow

	// GetTransforms returns the compiled version of the identity transformations and policies configured on the
	// FederationDomain for this identity provider.
	GetTransforms() *idtransform.TransformationPipeline

	// CloneIDPSpecificSessionDataFromSession should reach into the provided session and return a clone
	// of the field which is specific to the upstream identity provider type. If the session's field is
	// nil, then return nil.
	// Refer to the fields of psession.CustomSessionData whose types are specific to an identity provider type.
	CloneIDPSpecificSessionDataFromSession(session *psession.CustomSessionData) any

	// ApplyIDPSpecificSessionDataToSession assigns the IDP-specific portion of the session data into a session.
	// The IDP-specific session data provided to this function will be from an Identity that was returned by
	// one of the other functions of this interface, so an implementation of this function can make safe
	// assumptions about the type of idpSpecificSessionData for casting, based upon how it chooses to return
	// IDPSpecificSessionData in Identity structs. If the given session already has any IDP-specific session
	// data, it should be overwritten by this function.
	ApplyIDPSpecificSessionDataToSession(session *psession.CustomSessionData, idpSpecificSessionData any)

	// UpstreamAuthorizeRedirectURL returns the URL to which the user's browser can be redirected to continue
	// the downstream browser-based authorization flow. Returned errors should be of type fosite.RFC6749Error.
	UpstreamAuthorizeRedirectURL(state *UpstreamAuthorizeRequestState, downstreamIssuerURL string) (string, error)

	// LoginFromCallback handles an OAuth-style callback in a browser-based flow. This function should complete
	// the authorization with the upstream identity provider using the authCode, extract their upstream
	// identity, and transform it into their downstream identity. If the upstream does not allow PKCE, then
	// the pkce parameter can be ignored.
	// Returned errors should be from the httperr package.
	LoginFromCallback(ctx context.Context, authCode string, pkce pkce.Code, nonce nonce.Nonce, redirectURI string) (*Identity, *IdentityLoginExtras, error)

	// Login performs auth using a username and password that was submitted by the client, without a web browser.
	// This function should authenticate the user with the upstream identity provider, extract their upstream
	// identity, and transform it into their downstream identity.
	// Returned errors should be of type fosite.RFC6749Error.
	Login(ctx context.Context, submittedUsername string, submittedPassword string) (*Identity, *IdentityLoginExtras, error)

	// UpstreamRefresh performs a refresh with the upstream provider.
	// The user's previous identity information is provided as a parameter.
	// Implementations may use this information to assist in refreshes, but mutations to this argument will be ignored.
	// If possible, implementations should update the user's upstream group memberships by fetching them from the
	// upstream provider during the refresh, and returning them.
	// Returned errors should be of type fosite.RFC6749Error.
	UpstreamRefresh(ctx context.Context, identity *Identity) (refreshedIdentity *RefreshedIdentity, err error)
}

// ErrMissingUpstreamSessionInternalError returns a common type of error that can happen during a login or refresh.
func ErrMissingUpstreamSessionInternalError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "There was an internal server error.",
		HintField:        "Required upstream data not found in session.",
		CodeField:        http.StatusInternalServerError,
	}
}

// ErrUpstreamRefreshError returns a common type of error that can happen during a refresh.
func ErrUpstreamRefreshError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "Error during upstream refresh.",
		CodeField:        http.StatusUnauthorized,
	}
}
