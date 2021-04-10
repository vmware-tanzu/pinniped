// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"go.pinniped.dev/internal/mocks/mockldapconn"
	"go.pinniped.dev/internal/testutil"
)

var (
	upstreamUsername = "some-upstream-username"
	upstreamPassword = "some-upstream-password"
	upstreamGroups   = []string{"some-upstream-group-0", "some-upstream-group-1"}
	upstreamUID      = "some-upstream-uid"
)

func TestAuthenticateUser(t *testing.T) {
	// Please the linter...
	_ = upstreamGroups
	_ = upstreamUID
	t.Skip("TODO: make me pass!")

	tests := []struct {
		name                string
		provider            *Provider
		wantError           string
		wantUnauthenticated bool
		wantAuthResponse    *authenticator.Response
	}{
		{
			name: "happy path",
			provider: &Provider{
				Host:         "ldap.example.com:8443",
				BindUsername: upstreamUsername,
				BindPassword: upstreamPassword,
				UserSearch: &UserSearch{
					Base:              "some-upstream-base-dn",
					Filter:            "some-filter",
					UsernameAttribute: "some-upstream-username-attribute",
					UIDAttribute:      "some-upstream-uid-attribute",
				},
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   upstreamUsername,
					Groups: upstreamGroups,
					UID:    upstreamUID,
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			conn := mockldapconn.NewMockConn(ctrl)
			conn.EXPECT().Bind(test.provider.BindUsername, test.provider.BindPassword).Times(1)
			conn.EXPECT().Search(&ldap.SearchRequest{
				BaseDN:       test.provider.UserSearch.Base,
				Scope:        99, // TODO: what should this be?
				DerefAliases: 99, // TODO: what should this be?
				SizeLimit:    99,
				TimeLimit:    99,   // TODO: what should this be?
				TypesOnly:    true, // TODO: what should this be?
				Filter:       test.provider.UserSearch.Filter,
				Attributes:   []string{},       // TODO: what should this be?
				Controls:     []ldap.Control{}, // TODO: what should this be?
			}).Return(&ldap.SearchResult{
				Entries: []*ldap.Entry{
					{
						DN:         "",                       // TODO: what should this be?
						Attributes: []*ldap.EntryAttribute{}, // TODO: what should this be?
					},
				},
				Referrals: []string{},       // TODO: what should this be?
				Controls:  []ldap.Control{}, // TODO: what should this be?
			}, nil).Times(1)
			conn.EXPECT().Close().Times(1)

			dialWasAttempted := false
			test.provider.Dial = func(ctx context.Context, hostAndPort string) (Conn, error) {
				dialWasAttempted = true
				require.Equal(t, test.provider.Host, hostAndPort)
				return conn, nil
			}

			authResponse, authenticated, err := test.provider.AuthenticateUser(context.Background(), upstreamUsername, upstreamPassword)
			require.True(t, dialWasAttempted, "AuthenticateUser was supposed to try to dial, but didn't")
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.Equal(t, !test.wantUnauthenticated, authenticated)
			require.Equal(t, test.wantAuthResponse, authResponse)
		})
	}
}

func TestGetURL(t *testing.T) {
	require.Equal(t, "ldaps://ldap.example.com:1234", (&Provider{Host: "ldap.example.com:1234"}).GetURL())
	require.Equal(t, "ldaps://ldap.example.com", (&Provider{Host: "ldap.example.com"}).GetURL())
}

// Testing of host parsing, TLS negotiation, and CA bundle, etc. for the production code's dialer.
func TestRealTLSDialing(t *testing.T) {
	testServerCABundle, testServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	parsedURL, err := url.Parse(testServerURL)
	require.NoError(t, err)
	testServerHostAndPort := parsedURL.Host

	unusedPortGrabbingListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	recentlyClaimedHostAndPort := unusedPortGrabbingListener.Addr().String()
	require.NoError(t, unusedPortGrabbingListener.Close())

	alreadyCancelledContext, cancelFunc := context.WithCancel(context.Background())
	cancelFunc() // cancel it immediately

	tests := []struct {
		name      string
		host      string
		caBundle  []byte
		context   context.Context
		wantError string
	}{
		{
			name:     "happy path",
			host:     testServerHostAndPort,
			caBundle: []byte(testServerCABundle),
			context:  context.Background(),
		},
		{
			name:      "invalid CA bundle",
			host:      testServerHostAndPort,
			caBundle:  []byte("not a ca bundle"),
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": could not parse CA bundle`,
		},
		{
			name:      "missing CA bundle when it is required because the host is not using a trusted CA",
			host:      testServerHostAndPort,
			caBundle:  nil,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority`,
		},
		{
			name: "cannot connect to host",
			// This is assuming that this port was not reclaimed by another app since the test setup ran. Seems safe enough.
			host:      recentlyClaimedHostAndPort,
			caBundle:  []byte(testServerCABundle),
			context:   context.Background(),
			wantError: fmt.Sprintf(`LDAP Result Code 200 "Network Error": dial tcp %s: connect: connection refused`, recentlyClaimedHostAndPort),
		},
		{
			name:      "pays attention to the passed context",
			host:      testServerHostAndPort,
			caBundle:  []byte(testServerCABundle),
			context:   alreadyCancelledContext,
			wantError: fmt.Sprintf(`LDAP Result Code 200 "Network Error": dial tcp %s: operation was canceled`, testServerHostAndPort),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			provider := &Provider{
				Host:     test.host,
				CABundle: test.caBundle,
				Dial:     nil, // this test is for the default (production) dialer
			}
			conn, err := provider.dial(test.context)
			if conn != nil {
				defer conn.Close()
			}
			if test.wantError != "" {
				require.Nil(t, conn)
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				require.NotNil(t, conn)

				// Should be an instance of the real production LDAP client type.
				// Can't test its methods here because we are not dialed to a real LDAP server.
				require.IsType(t, &ldap.Conn{}, conn)

				// Indirectly checking that the Dial method constructed the ldap.Conn with isTLS set to true,
				// since this is always the correct behavior unless/until we want to support StartTLS.
				err := conn.(*ldap.Conn).StartTLS(&tls.Config{})
				require.EqualError(t, err, `LDAP Result Code 200 "Network Error": ldap: already encrypted`)
			}
		})
	}
}

// Test various cases of host and port parsing.
func TestHostAndPortWithDefaultPort(t *testing.T) {
	tests := []struct {
		name            string
		hostAndPort     string
		defaultPort     string
		wantError       string
		wantHostAndPort string
	}{
		{
			name:            "host already has port",
			hostAndPort:     "host.example.com:99",
			defaultPort:     "42",
			wantHostAndPort: "host.example.com:99",
		},
		{
			name:            "host does not have port",
			hostAndPort:     "host.example.com",
			defaultPort:     "42",
			wantHostAndPort: "host.example.com:42",
		},
		{
			name:            "host does not have port and default port is empty",
			hostAndPort:     "host.example.com",
			defaultPort:     "",
			wantHostAndPort: "host.example.com",
		},
		{
			name:            "IPv6 host already has port",
			hostAndPort:     "[::1%lo0]:80",
			defaultPort:     "42",
			wantHostAndPort: "[::1%lo0]:80",
		},
		{
			name:            "IPv6 host does not have port",
			hostAndPort:     "[::1%lo0]",
			defaultPort:     "42",
			wantHostAndPort: "[::1%lo0]:42",
		},
		{
			name:            "IPv6 host does not have port and default port is empty",
			hostAndPort:     "[::1%lo0]",
			defaultPort:     "",
			wantHostAndPort: "[::1%lo0]",
		},
		{
			name:        "host is not valid",
			hostAndPort: "host.example.com:port1:port2",
			defaultPort: "42",
			wantError:   "address host.example.com:port1:port2: too many colons in address",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			hostAndPort, err := hostAndPortWithDefaultPort(test.hostAndPort, test.defaultPort)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.wantHostAndPort, hostAndPort)
		})
	}
}
