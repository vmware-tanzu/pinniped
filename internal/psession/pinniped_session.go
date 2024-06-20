// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package psession

import (
	"maps"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
	"k8s.io/apimachinery/pkg/types"
)

// PinnipedSession is a session container which includes the fosite standard stuff plus custom Pinniped stuff.
type PinnipedSession struct {
	// Delegate most things to the standard fosite OpenID JWT session.
	Fosite *openid.DefaultSession `json:"fosite,omitempty"`

	// Custom Pinniped extensions to the session data.
	Custom *CustomSessionData `json:"custom,omitempty"`
}

var _ openid.Session = &PinnipedSession{}

// CustomSessionData is the custom session data needed by Pinniped. It should be treated as a union type,
// where the value of ProviderType decides which other fields to use.
type CustomSessionData struct {
	// Username will contain the downstream username determined during initial authorization. We store this
	// so that we can validate that it does not change upon refresh. This should normally never be empty, since
	// all users must have a username.
	Username string `json:"username"`

	// UpstreamUsername is the username from the upstream identity provider during the user's initial login before
	// identity transformations were applied. We store this so that we can still reapply identity transformations
	// during refresh flows even when an upstream OIDC provider does not return the username again during the upstream
	// refresh, and so we can validate that same untransformed username was found during an LDAP refresh.
	UpstreamUsername string `json:"upstreamUsername"`

	// UpstreamGroups is the groups list from the upstream identity provider during the user's initial login before
	// identity transformations were applied. We store this so that we can still reapply identity transformations
	// during refresh flows even when an OIDC provider does not return the groups again during the upstream
	// refresh, and when the LDAP search was configured to skip group refreshes.
	UpstreamGroups []string `json:"upstreamGroups"`

	// The Kubernetes resource UID of the identity provider CRD for the upstream IDP used to start this session.
	// This should be validated again upon downstream refresh to make sure that we are not refreshing against
	// a different identity provider CRD which just happens to have the same name.
	// This implies that when a user deletes an identity provider CRD, then the sessions that were started
	// using that identity provider will not be able to perform any more downstream refreshes.
	ProviderUID types.UID `json:"providerUID"`

	// The Kubernetes resource name of the identity provider CRD for the upstream IDP used to start this session.
	// Used during a downstream refresh to decide which upstream to refresh.
	// Also used by the session storage garbage collector to decide which upstream to use for token revocation.
	ProviderName string `json:"providerName"`

	// The type of the identity provider for the upstream IDP used to start this session.
	// Used during a downstream refresh to decide which upstream to refresh.
	// Also used to decide which of the pointer types below should be used.
	ProviderType ProviderType `json:"providerType"`

	// Warnings that were encountered at some point during login that should be emitted to the client.
	// These will be RFC 2616-formatted errors with error code 299.
	Warnings []string `json:"warnings"`

	// Only used when ProviderType == "oidc".
	OIDC *OIDCSessionData `json:"oidc,omitempty"`

	// Only used when ProviderType == "ldap".
	LDAP *LDAPSessionData `json:"ldap,omitempty"`

	// Only used when ProviderType == "activedirectory".
	ActiveDirectory *ActiveDirectorySessionData `json:"activedirectory,omitempty"`

	// Only used when ProviderType == "github".
	GitHub *GitHubSessionData `json:"github,omitempty"`
}

type ProviderType string

const (
	ProviderTypeOIDC            ProviderType = "oidc"
	ProviderTypeLDAP            ProviderType = "ldap"
	ProviderTypeActiveDirectory ProviderType = "activedirectory"
	ProviderTypeGitHub          ProviderType = "github"
)

// OIDCSessionData is the additional data needed by Pinniped when the upstream IDP is an OIDC provider.
type OIDCSessionData struct {
	// UpstreamRefreshToken will contain the refresh token from the upstream OIDC provider, if the upstream provider
	// returned a refresh token during initial authorization. Otherwise, this field should be empty
	// and the UpstreamAccessToken should be non-empty. We may not get a refresh token from the upstream provider,
	// but we should always get an access token. However, when we do get a refresh token there is no need to
	// also store the access token, since storing unnecessary tokens makes it possible for them to be leaked and
	// creates more upstream revocation HTTP requests when it comes time to revoke the stored tokens.
	UpstreamRefreshToken string `json:"upstreamRefreshToken"`

	// UpstreamAccessToken will contain the access token returned by the upstream OIDC provider during initial
	// authorization, but only when the provider did not also return a refresh token. When UpstreamRefreshToken is
	// non-empty, then this field should be empty, indicating that we should use the upstream refresh token during
	// downstream refresh.
	UpstreamAccessToken string `json:"upstreamAccessToken"`

	// UpstreamSubject is the "sub" claim from the upstream identity provider from the user's initial login. We store this
	// so that we can validate that it does not change upon refresh.
	UpstreamSubject string `json:"upstreamSubject"`

	// UpstreamIssuer is the "iss" claim from the upstream identity provider from the user's initial login. We store this
	// so that we can validate that it does not change upon refresh.
	UpstreamIssuer string `json:"upstreamIssuer"`
}

func (s *OIDCSessionData) Clone() *OIDCSessionData {
	dataCopy := *s // this shortcut works because all fields in this type are currently strings (no pointers)
	return &dataCopy
}

// LDAPSessionData is the additional data needed by Pinniped when the upstream IDP is an LDAP provider.
type LDAPSessionData struct {
	UserDN                 string            `json:"userDN"`
	ExtraRefreshAttributes map[string]string `json:"extraRefreshAttributes,omitempty"`
}

func (s *LDAPSessionData) Clone() *LDAPSessionData {
	return &LDAPSessionData{
		UserDN:                 s.UserDN,
		ExtraRefreshAttributes: maps.Clone(s.ExtraRefreshAttributes), // shallow copy works because all keys and values are strings
	}
}

// ActiveDirectorySessionData is the additional data needed by Pinniped when the upstream IDP is an Active Directory provider.
type ActiveDirectorySessionData struct {
	UserDN                 string            `json:"userDN"`
	ExtraRefreshAttributes map[string]string `json:"extraRefreshAttributes,omitempty"`
}

func (s *ActiveDirectorySessionData) Clone() *ActiveDirectorySessionData {
	return &ActiveDirectorySessionData{
		UserDN:                 s.UserDN,
		ExtraRefreshAttributes: maps.Clone(s.ExtraRefreshAttributes), // shallow copy works because all keys and values are strings
	}
}

type GitHubSessionData struct {
	UpstreamAccessToken string `json:"upstreamAccessToken"`
}

func (s *GitHubSessionData) Clone() *GitHubSessionData {
	dataCopy := *s // this shortcut works because all fields in this type are currently strings (no pointers)
	return &dataCopy
}

// NewPinnipedSession returns a new empty session.
func NewPinnipedSession() *PinnipedSession {
	return &PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims:  &fositejwt.IDTokenClaims{},
			Headers: &fositejwt.Headers{},
		},
		Custom: &CustomSessionData{},
	}
}

func (s *PinnipedSession) Clone() fosite.Session {
	// Implementation copied from openid.DefaultSession's clone method.
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}

func (s *PinnipedSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	s.Fosite.SetExpiresAt(key, exp)
}

func (s *PinnipedSession) GetExpiresAt(key fosite.TokenType) time.Time {
	return s.Fosite.GetExpiresAt(key)
}

func (s *PinnipedSession) GetUsername() string {
	return s.Fosite.GetUsername()
}

func (s *PinnipedSession) SetSubject(subject string) {
	s.Fosite.SetSubject(subject)
}

func (s *PinnipedSession) GetSubject() string {
	return s.Fosite.GetSubject()
}

func (s *PinnipedSession) IDTokenHeaders() *fositejwt.Headers {
	return s.Fosite.IDTokenHeaders()
}

func (s *PinnipedSession) IDTokenClaims() *fositejwt.IDTokenClaims {
	return s.Fosite.IDTokenClaims()
}
