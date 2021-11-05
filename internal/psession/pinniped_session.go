// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package psession

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
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
	// The Kubernetes resource UID of the identity provider CRD for the upstream IDP used to start this session.
	// This should be validated again upon downstream refresh to make sure that we are not refreshing against
	// a different identity provider CRD which just happens to have the same name.
	// This implies that when a user deletes an identity provider CRD, then the sessions that were started
	// using that identity provider will not be able to perform any more downstream refreshes.
	ProviderUID types.UID `json:"providerUID"`

	// The Kubernetes resource name of the identity provider CRD for the upstream IDP used to start this session.
	// Used during a downstream refresh to decide which upstream to refresh.
	// Also used to decide which of the pointer types below should be used.
	ProviderName string `json:"providerName"`

	// The type of the identity provider for the upstream IDP used to start this session.
	// Used during a downstream refresh to decide which upstream to refresh.
	ProviderType ProviderType `json:"providerType"`

	// Only used when ProviderType == "oidc".
	OIDC *OIDCSessionData `json:"oidc,omitempty"`

	LDAP *LDAPSessionData `json:"ldap,omitempty"`

	ActiveDirectory *ActiveDirectorySessionData `json:"activedirectory,omitempty"`
}

type ProviderType string

const (
	ProviderTypeOIDC            ProviderType = "oidc"
	ProviderTypeLDAP            ProviderType = "ldap"
	ProviderTypeActiveDirectory ProviderType = "activedirectory"
)

// OIDCSessionData is the additional data needed by Pinniped when the upstream IDP is an OIDC provider.
type OIDCSessionData struct {
	UpstreamRefreshToken string `json:"upstreamRefreshToken"`
}

// LDAPSessionData is the additional data needed by Pinniped when the upstream IDP is an LDAP provider.
type LDAPSessionData struct {
	UserDN string `json:"userDN"`
}

// ActiveDirectorySessionData is the additional data needed by Pinniped when the upstream IDP is an Active Directory provider.
type ActiveDirectorySessionData struct {
	UserDN string `json:"userDN"`
}

// NewPinnipedSession returns a new empty session.
func NewPinnipedSession() *PinnipedSession {
	return &PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{},
			Headers: &jwt.Headers{},
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

func (s *PinnipedSession) IDTokenHeaders() *jwt.Headers {
	return s.Fosite.IDTokenHeaders()
}

func (s *PinnipedSession) IDTokenClaims() *jwt.IDTokenClaims {
	return s.Fosite.IDTokenClaims()
}
