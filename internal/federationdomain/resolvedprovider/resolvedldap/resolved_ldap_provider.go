// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedldap

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/federationdomain/downstreamsubject"
	"go.pinniped.dev/internal/federationdomain/endpoints/loginurl"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// FederationDomainResolvedLDAPIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamLDAPIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedLDAPIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamLDAPIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

var _ resolvedprovider.FederationDomainResolvedIdentityProvider = (*FederationDomainResolvedLDAPIdentityProvider)(nil)

func (p *FederationDomainResolvedLDAPIdentityProvider) GetDisplayName() string {
	return p.DisplayName
}

func (p *FederationDomainResolvedLDAPIdentityProvider) GetProvider() upstreamprovider.UpstreamIdentityProviderI {
	return p.Provider
}

func (p *FederationDomainResolvedLDAPIdentityProvider) GetSessionProviderType() psession.ProviderType {
	return p.SessionProviderType
}

func (p *FederationDomainResolvedLDAPIdentityProvider) GetIDPDiscoveryType() v1alpha1.IDPType {
	if p.GetSessionProviderType() == psession.ProviderTypeActiveDirectory {
		return v1alpha1.IDPTypeActiveDirectory
	}
	return v1alpha1.IDPTypeLDAP
}

func (p *FederationDomainResolvedLDAPIdentityProvider) GetIDPDiscoveryFlows() []v1alpha1.IDPFlow {
	return []v1alpha1.IDPFlow{v1alpha1.IDPFlowCLIPassword, v1alpha1.IDPFlowBrowserAuthcode}
}

func (p *FederationDomainResolvedLDAPIdentityProvider) GetTransforms() *idtransform.TransformationPipeline {
	return p.Transforms
}

func (p *FederationDomainResolvedLDAPIdentityProvider) CloneIDPSpecificSessionDataFromSession(session *psession.CustomSessionData) interface{} {
	switch p.GetSessionProviderType() {
	case psession.ProviderTypeLDAP:
		if session.LDAP == nil {
			return nil
		}
		return session.LDAP.Clone()
	case psession.ProviderTypeActiveDirectory:
		if session.ActiveDirectory == nil {
			return nil
		}
		return session.ActiveDirectory.Clone()
	case psession.ProviderTypeOIDC: // this is just here to avoid a lint error about not handling all cases
		fallthrough
	default:
		return nil
	}
}

func (p *FederationDomainResolvedLDAPIdentityProvider) ApplyIDPSpecificSessionDataToSession(session *psession.CustomSessionData, idpSpecificSessionData interface{}) {
	if p.GetSessionProviderType() == psession.ProviderTypeActiveDirectory {
		session.ActiveDirectory = idpSpecificSessionData.(*psession.ActiveDirectorySessionData)
		return
	}
	session.LDAP = idpSpecificSessionData.(*psession.LDAPSessionData)
}

func (p *FederationDomainResolvedLDAPIdentityProvider) UpstreamAuthorizeRedirectURL(state *resolvedprovider.UpstreamAuthorizeRequestState, downstreamIssuerURL string) (string, error) {
	loginURL, err := loginurl.URL(downstreamIssuerURL, state.EncodedStateParam, loginurl.ShowNoError)
	if err != nil {
		return "", fosite.ErrServerError.WithHint("Server could not formulate login UI URL for redirect.").WithWrap(err)
	}

	return loginURL, nil
}

// These are special errors that can be returned by Login for a FederationDomainResolvedLDAPIdentityProvider.
var (
	// ErrUnexpectedUpstreamLDAPError is returned by Login when there was an unexpected error during LDAP auth.
	// The error returned from Login() should be compared to this using errors.Is().
	ErrUnexpectedUpstreamLDAPError = &fosite.RFC6749Error{
		ErrorField:       "error", // this string matches what fosite uses for generic errors
		DescriptionField: "Unexpected error during upstream LDAP authentication.",
		CodeField:        http.StatusBadGateway,
	}

	// ErrAccessDeniedDueToUsernamePasswordNotAccepted is returned by Login when the LDAP auth failed due to a
	// bad username or password. Due to the way that fosite implements RFC6749Error.Is(), you must use "=="
	// to compare this error to an error returned from Login().
	ErrAccessDeniedDueToUsernamePasswordNotAccepted = &fosite.RFC6749Error{
		ErrorField:       "access_denied", // this string matches what fosite uses for access denied errors
		DescriptionField: "The resource owner or authorization server denied the request.",
		HintField:        "Username/password not accepted by LDAP provider.",
		CodeField:        http.StatusForbidden,
	}
)

func (p *FederationDomainResolvedLDAPIdentityProvider) Login(
	ctx context.Context,
	submittedUsername string,
	submittedPassword string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	authenticateResponse, authenticated, err := p.Provider.AuthenticateUser(ctx, submittedUsername, submittedPassword)
	if err != nil {
		plog.WarningErr("unexpected error during upstream LDAP authentication", err, "upstreamName", p.Provider.GetName())
		return nil, nil, ErrUnexpectedUpstreamLDAPError.WithWrap(err)
	}
	if !authenticated {
		return nil, nil, ErrAccessDeniedDueToUsernamePasswordNotAccepted
	}

	subject := downstreamSubjectFromUpstreamLDAP(p.Provider, authenticateResponse, p.GetDisplayName())
	upstreamUsername := authenticateResponse.User.GetName()
	upstreamGroups := authenticateResponse.User.GetGroups()

	var sessionData interface{}
	switch p.GetSessionProviderType() {
	case psession.ProviderTypeLDAP:
		sessionData = &psession.LDAPSessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	case psession.ProviderTypeActiveDirectory:
		sessionData = &psession.ActiveDirectorySessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	case psession.ProviderTypeOIDC: // this is just here to avoid a lint error about not handling all cases
		fallthrough
	default:
		return nil, nil, ErrUnexpectedUpstreamLDAPError.WithWrap(fmt.Errorf("unexpected provider type %q", p.GetSessionProviderType()))
	}

	return &resolvedprovider.Identity{
			UpstreamUsername:       upstreamUsername,
			UpstreamGroups:         upstreamGroups,
			DownstreamSubject:      subject,
			IDPSpecificSessionData: sessionData,
		},
		&resolvedprovider.IdentityLoginExtras{
			DownstreamAdditionalClaims: nil,
			Warnings:                   nil,
		},
		nil
}

func (p *FederationDomainResolvedLDAPIdentityProvider) LoginFromCallback(
	_ctx context.Context,
	_authCode string,
	_pkce pkce.Code,
	_nonce nonce.Nonce,
	_redirectURI string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	return nil, nil, httperr.New(http.StatusInternalServerError,
		"LoginFromCallback() is not supported for LDAP and ActiveDirectory types of identity provider")
}

func (p *FederationDomainResolvedLDAPIdentityProvider) UpstreamRefresh(
	ctx context.Context,
	identity *resolvedprovider.Identity,
) (refreshedIdentity *resolvedprovider.RefreshedIdentity, err error) {
	var dn string
	var additionalAttributes map[string]string

	switch p.GetSessionProviderType() {
	case psession.ProviderTypeLDAP:
		sessionData, ok := identity.IDPSpecificSessionData.(*psession.LDAPSessionData)
		if !ok {
			// This shouldn't really happen.
			return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
		}
		dn = sessionData.UserDN
		additionalAttributes = sessionData.ExtraRefreshAttributes
	case psession.ProviderTypeActiveDirectory:
		sessionData, ok := identity.IDPSpecificSessionData.(*psession.ActiveDirectorySessionData)
		if !ok {
			// This shouldn't really happen.
			return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
		}
		dn = sessionData.UserDN
		additionalAttributes = sessionData.ExtraRefreshAttributes
	case psession.ProviderTypeOIDC: // this is just here to avoid a lint error about not handling all cases
		fallthrough
	default:
		// This shouldn't really happen.
		return nil, resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Unexpected provider type during refresh %q", p.GetSessionProviderType()).WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", p.Provider.GetName(), p.GetSessionProviderType())
	}

	if dn == "" {
		return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	plog.Debug("attempting upstream refresh request",
		"providerName", p.Provider.GetName(), "providerType", p.GetSessionProviderType(), "providerUID", p.Provider.GetResourceUID())

	refreshedUntransformedGroups, err := p.Provider.PerformRefresh(ctx, upstreamprovider.RefreshAttributes{
		Username:             identity.UpstreamUsername,
		Subject:              identity.DownstreamSubject,
		DN:                   dn,
		Groups:               identity.UpstreamGroups,
		AdditionalAttributes: additionalAttributes,
	}, p.GetDisplayName())
	if err != nil {
		return nil, resolvedprovider.ErrUpstreamRefreshError().WithHint(
			"Upstream refresh failed.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", p.Provider.GetName(), p.GetSessionProviderType())
	}

	return &resolvedprovider.RefreshedIdentity{
		// LDAP PerformRefresh validates that the username did not change during refresh,
		// so the original upstream username is also the refreshed upstream username.
		UpstreamUsername:       identity.UpstreamUsername,
		UpstreamGroups:         refreshedUntransformedGroups,
		IDPSpecificSessionData: nil,
	}, nil
}

func downstreamSubjectFromUpstreamLDAP(
	ldapUpstream upstreamprovider.UpstreamLDAPIdentityProviderI,
	authenticateResponse *authenticators.Response,
	idpDisplayName string,
) string {
	ldapURL := *ldapUpstream.GetURL()
	return downstreamsubject.LDAP(authenticateResponse.User.GetUID(), ldapURL, idpDisplayName)
}
