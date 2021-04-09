// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamldap implements an abstraction of upstream LDAP IDP interactions.
package upstreamldap

import (
	"context"

	ldap "github.com/go-ldap/ldap/v3"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// Conn abstracts the upstream LDAP communication protocol (mostly for testing).
type Conn interface {
	// Bind abstracts ldap.Conn.Bind().
	Bind(username, password string) error
	// Search abstracts ldap.Conn.Search().
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	// Close abstracts ldap.Conn.Close().
	Close()
}

// UserSearch contains information about how to search for users in the upstream LDAP IDP.
type UserSearch struct {
	// Base is the base DN to use for the user search in the upstream LDAP IDP.
	Base string
	// Filter is the filter to use for the user search in the upstream LDAP IDP.
	Filter string
	// UsernameAttribute is the attribute in the LDAP entry from which the username should be
	// retrieved.
	UsernameAttribute string
	// UIDAttribute is the attribute in the LDAP entry from which the user's unique ID should be
	// retrieved.
	UIDAttribute string
}

// Provider contains can interact with an upstream LDAP IDP.
type Provider struct {
	// Name is the unique name of this upstream LDAP IDP.
	Name string
	// URL is the URL of this upstream LDAP IDP.
	URL string

	// Dial is a func that, given a URL, will return an LDAPConn to use for communicating with an
	// upstream LDAP IDP.
	Dial func(ctx context.Context, url string) (Conn, error)

	// BindUsername is the username to use when performing a bind with the upstream LDAP IDP.
	BindUsername string
	// BindPassword is the password to use when performing a bind with the upstream LDAP IDP.
	BindPassword string

	// UserSearch contains information about how to search for users in the upstream LDAP IDP.
	UserSearch *UserSearch
}

func (p *Provider) GetName() string {
	return p.Name
}

func (p *Provider) GetURL() string {
	return p.URL
}

func (p *Provider) AuthenticateUser(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
	// TODO: test context timeout?
	// TODO: test dial context timeout?
	return nil, false, nil
}
