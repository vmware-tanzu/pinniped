// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamldap implements an abstraction of upstream LDAP IDP interactions.
package upstreamldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const (
	ldapsScheme = "ldaps"
)

// Conn abstracts the upstream LDAP communication protocol (mostly for testing).
type Conn interface {
	Bind(username, password string) error

	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)

	Close()
}

// Our Conn type is subset of the ldap.Client interface, which is implemented by ldap.Conn.
var _ Conn = &ldap.Conn{}

// LDAPDialer is a factory of Conn, and the resulting Conn can then be used to interact with an upstream LDAP IDP.
type LDAPDialer interface {
	Dial(ctx context.Context, hostAndPort string) (Conn, error)
}

// LDAPDialerFunc makes it easy to use a func as an LDAPDialer.
type LDAPDialerFunc func(ctx context.Context, hostAndPort string) (Conn, error)

func (f LDAPDialerFunc) Dial(ctx context.Context, hostAndPort string) (Conn, error) {
	return f(ctx, hostAndPort)
}

// Provider includes all of the settings for connection and searching for users and groups in
// the upstream LDAP IDP. It also provides methods for testing the connection and performing logins.
type Provider struct {
	// Name is the unique name of this upstream LDAP IDP.
	Name string

	// Host is the hostname or "hostname:port" of the LDAP server. When the port is not specified,
	// the default LDAP port will be used.
	Host string

	// PEM-encoded CA cert bundle to trust when connecting to the LDAP server.
	CABundle []byte

	// BindUsername is the username to use when performing a bind with the upstream LDAP IDP.
	BindUsername string

	// BindPassword is the password to use when performing a bind with the upstream LDAP IDP.
	BindPassword string

	// UserSearch contains information about how to search for users in the upstream LDAP IDP.
	UserSearch *UserSearch

	// Dialer exists to enable testing. When nil, will use a default appropriate for production use.
	Dialer LDAPDialer
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

func (p *Provider) dial(ctx context.Context) (Conn, error) {
	hostAndPort, err := hostAndPortWithDefaultPort(p.Host, ldap.DefaultLdapsPort)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}
	if p.Dialer != nil {
		return p.Dialer.Dial(ctx, hostAndPort)
	}
	return p.dialTLS(ctx, hostAndPort)
}

// dialTLS is the default implementation of the Dialer, used when Dialer is nil.
// Unfortunately, the go-ldap library does not seem to support dialing with a context.Context,
// so we implement it ourselves, heavily inspired by ldap.DialURL.
func (p *Provider) dialTLS(ctx context.Context, hostAndPort string) (Conn, error) {
	rootCAs := x509.NewCertPool()
	if p.CABundle != nil {
		if !rootCAs.AppendCertsFromPEM(p.CABundle) {
			return nil, ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("could not parse CA bundle"))
		}
	}

	dialer := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}}

	c, err := dialer.DialContext(ctx, "tcp", hostAndPort)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	conn := ldap.NewConn(c, true)
	conn.Start()
	return conn, nil
}

// Adds the default port if hostAndPort did not already include a port.
func hostAndPortWithDefaultPort(hostAndPort string, defaultPort string) (string, error) {
	host, port, err := net.SplitHostPort(hostAndPort)
	if err != nil {
		if strings.HasSuffix(err.Error(), ": missing port in address") { // sad to need to do this string compare
			host = hostAndPort
			port = defaultPort
		} else {
			return "", err // hostAndPort argument was not parsable
		}
	}
	switch {
	case port != "" && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		// don't add extra square brackets to an IPv6 address that already has them
		return host + ":" + port, nil
	case port != "":
		return net.JoinHostPort(host, port), nil
	default:
		return host, nil
	}
}

// A name for this upstream provider.
func (p *Provider) GetName() string {
	return p.Name
}

// Return a URL which uniquely identifies this LDAP provider, e.g. "ldaps://host.example.com:1234".
// This URL is not used for connecting to the provider, but rather is used for creating a globally unique user
// identifier by being combined with the user's UID, since user UIDs are only unique within one provider.
func (p *Provider) GetURL() string {
	return fmt.Sprintf("%s://%s", ldapsScheme, p.Host)
}

// TestConnection provides a method for testing the connection and bind settings by dialing and binding.
func (p *Provider) TestConnection(ctx context.Context) error {
	_, _ = p.dial(ctx)
	// TODO bind using the bind credentials
	// TODO close
	// TODO return any dial or bind errors
	return nil
}

// Authenticate a user and return their mapped username, groups, and UID. Implements authenticators.UserAuthenticator.
func (p *Provider) AuthenticateUser(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
	_, _ = p.dial(ctx)
	// TODO bind
	// TODO user search
	// TODO user bind
	// TODO map username and uid attributes
	// TODO group search
	// TODO map group attributes
	// TODO close
	// TODO return any errors that were encountered along the way
	return nil, false, nil
}
