// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamldap

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"go.pinniped.dev/internal/mocks/mockldapconn"
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
				URL:          "ldaps://some-ldap-url:1234",
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

			test.provider.Dial = func(ctx context.Context, url string) (Conn, error) {
				require.Equal(t, test.provider.URL, url)
				return conn, nil
			}

			authResponse, authenticated, err := test.provider.AuthenticateUser(context.Background(), upstreamUsername, upstreamPassword)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}
			require.Equal(t, !test.wantUnauthenticated, authenticated)
			require.Equal(t, test.wantAuthResponse, authResponse)
		})
	}
}
