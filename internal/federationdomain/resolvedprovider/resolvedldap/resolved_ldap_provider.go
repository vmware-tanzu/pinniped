// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedldap

import (
	"context"
	"net/http"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/federationdomain/downstreamsession"
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
	groupsWillBeIgnored bool,
) (*resolvedprovider.Identity, error) {
	authenticateResponse, authenticated, err := p.Provider.AuthenticateUser(ctx, submittedUsername, submittedPassword, groupsWillBeIgnored)
	if err != nil {
		plog.WarningErr("unexpected error during upstream LDAP authentication", err, "upstreamName", p.Provider.GetName())
		return nil, ErrUnexpectedUpstreamLDAPError.WithWrap(err)
	}
	if !authenticated {
		return nil, ErrAccessDeniedDueToUsernamePasswordNotAccepted
	}

	subject := downstreamSubjectFromUpstreamLDAP(p.Provider, authenticateResponse, p.DisplayName)
	upstreamUsername := authenticateResponse.User.GetName()
	upstreamGroups := authenticateResponse.User.GetGroups()

	username, groups, err := downstreamsession.ApplyIdentityTransformations(ctx, p.Transforms, upstreamUsername, upstreamGroups)
	if err != nil {
		return nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	customSessionData := makeDownstreamLDAPOrADCustomSessionData(
		p.Provider, p.SessionProviderType, authenticateResponse, username, upstreamUsername, upstreamGroups)

	return &resolvedprovider.Identity{
		SessionData: customSessionData,
		Groups:      groups,
		Subject:     subject,
	}, nil
}

func (p *FederationDomainResolvedLDAPIdentityProvider) HandleCallback(
	_ctx context.Context,
	_authCode string,
	_pkce pkce.Code,
	_nonce nonce.Nonce,
	_redirectURI string,
) (*resolvedprovider.Identity, error) {
	return nil, httperr.New(http.StatusInternalServerError, "not supported for this type of identity provider")
}

func (p *FederationDomainResolvedLDAPIdentityProvider) UpstreamRefresh(
	ctx context.Context,
	session *psession.PinnipedSession,
	groupsWillBeIgnored bool,
) (refreshedGroups []string, err error) {
	s := session.Custom

	var dn string
	if s.ProviderType == psession.ProviderTypeLDAP {
		dn = s.LDAP.UserDN
	} else if s.ProviderType == psession.ProviderTypeActiveDirectory {
		dn = s.ActiveDirectory.UserDN
	}

	validLDAP := s.ProviderType == psession.ProviderTypeLDAP && s.LDAP != nil && s.LDAP.UserDN != ""
	validAD := s.ProviderType == psession.ProviderTypeActiveDirectory && s.ActiveDirectory != nil && s.ActiveDirectory.UserDN != ""
	if !(validLDAP || validAD) {
		return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	var additionalAttributes map[string]string
	if s.ProviderType == psession.ProviderTypeLDAP {
		additionalAttributes = s.LDAP.ExtraRefreshAttributes
	} else {
		additionalAttributes = s.ActiveDirectory.ExtraRefreshAttributes
	}

	if session.IDTokenClaims().AuthTime.IsZero() {
		return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	oldTransformedUsername := session.Custom.Username
	oldUntransformedUsername := session.Custom.UpstreamUsername
	oldUntransformedGroups := session.Custom.UpstreamGroups

	plog.Debug("attempting upstream refresh request",
		"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)

	refreshedUntransformedGroups, err := p.Provider.PerformRefresh(ctx, upstreamprovider.RefreshAttributes{
		Username:             oldUntransformedUsername,
		Subject:              session.Fosite.Claims.Subject,
		DN:                   dn,
		Groups:               oldUntransformedGroups,
		AdditionalAttributes: additionalAttributes,
		SkipGroups:           groupsWillBeIgnored,
	}, p.DisplayName)
	if err != nil {
		return nil, resolvedprovider.ErrUpstreamRefreshError().WithHint(
			"Upstream refresh failed.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}

	transformationResult, err := resolvedprovider.TransformRefreshedIdentity(ctx,
		p.Transforms,
		oldTransformedUsername,
		oldUntransformedUsername, // LDAP PerformRefresh validates that the username did not change, so this is also the refreshed upstream username
		refreshedUntransformedGroups,
		s.ProviderName,
		s.ProviderType,
	)
	if err != nil {
		return nil, err
	}

	return transformationResult.Groups, nil
}

func makeDownstreamLDAPOrADCustomSessionData(
	ldapUpstream upstreamprovider.UpstreamLDAPIdentityProviderI,
	idpType psession.ProviderType,
	authenticateResponse *authenticators.Response,
	username string,
	untransformedUpstreamUsername string,
	untransformedUpstreamGroups []string,
) *psession.CustomSessionData {
	customSessionData := &psession.CustomSessionData{
		Username:         username,
		UpstreamUsername: untransformedUpstreamUsername,
		UpstreamGroups:   untransformedUpstreamGroups,
		ProviderUID:      ldapUpstream.GetResourceUID(),
		ProviderName:     ldapUpstream.GetName(),
		ProviderType:     idpType,
	}

	if idpType == psession.ProviderTypeLDAP {
		customSessionData.LDAP = &psession.LDAPSessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	}

	if idpType == psession.ProviderTypeActiveDirectory {
		customSessionData.ActiveDirectory = &psession.ActiveDirectorySessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	}

	return customSessionData
}

func downstreamSubjectFromUpstreamLDAP(
	ldapUpstream upstreamprovider.UpstreamLDAPIdentityProviderI,
	authenticateResponse *authenticators.Response,
	idpDisplayName string,
) string {
	ldapURL := *ldapUpstream.GetURL()
	return downstreamsubject.LDAP(authenticateResponse.User.GetUID(), ldapURL, idpDisplayName)
}
