// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamldap

import (
	"context"
	"crypto/tls"
	"errors"
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

const (
	testHost                               = "ldap.example.com:8443"
	testBindUsername                       = "cn=some-bind-username,dc=pinniped,dc=dev"
	testBindPassword                       = "some-bind-password"
	testUpstreamUsername                   = "some-upstream-username"
	testUpstreamPassword                   = "some-upstream-password"
	testUserSearchBase                     = "some-upstream-base-dn"
	testUserSearchFilter                   = "some-filter={}-and-more-filter={}"
	testUserSearchUsernameAttribute        = "some-upstream-username-attribute"
	testUserSearchUIDAttribute             = "some-upstream-uid-attribute"
	testSearchResultDNValue                = "some-upstream-user-dn"
	testSearchResultUsernameAttributeValue = "some-upstream-username-value"
	testSearchResultUIDAttributeValue      = "some-upstream-uid-value"
)

var (
	testUserSearchFilterInterpolated = fmt.Sprintf("(some-filter=%s-and-more-filter=%s)", testUpstreamUsername, testUpstreamUsername)
)

func TestEndUserAuthentication(t *testing.T) {
	providerConfig := func(editFunc func(p *ProviderConfig)) *ProviderConfig {
		config := &ProviderConfig{
			Name:         "some-provider-name",
			Host:         testHost,
			CABundle:     nil, // this field is only used by the production dialer, which is replaced by a mock for this test
			BindUsername: testBindUsername,
			BindPassword: testBindPassword,
			UserSearch: UserSearchConfig{
				Base:              testUserSearchBase,
				Filter:            testUserSearchFilter,
				UsernameAttribute: testUserSearchUsernameAttribute,
				UIDAttribute:      testUserSearchUIDAttribute,
			},
		}
		if editFunc != nil {
			editFunc(config)
		}
		return config
	}

	expectedSearch := func(editFunc func(r *ldap.SearchRequest)) *ldap.SearchRequest {
		request := &ldap.SearchRequest{
			BaseDN:       testUserSearchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.DerefAlways,
			SizeLimit:    2,
			TimeLimit:    90,
			TypesOnly:    false,
			Filter:       testUserSearchFilterInterpolated,
			Attributes:   []string{testUserSearchUsernameAttribute, testUserSearchUIDAttribute},
			Controls:     nil,
		}
		if editFunc != nil {
			editFunc(request)
		}
		return request
	}

	tests := []struct {
		name                       string
		username                   string
		password                   string
		providerConfig             *ProviderConfig
		searchMocks                func(conn *mockldapconn.MockConn)
		bindEndUserMocks           func(conn *mockldapconn.MockConn)
		dialError                  error
		wantError                  string
		wantToSkipDial             bool
		wantAuthResponse           *authenticator.Response
		wantUnauthenticated        bool
		skipDryRunAuthenticateUser bool // tests about when the end user bind fails don't make sense for DryRunAuthenticateUser()
	}{
		{
			name:           "happy path",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
					Referrals: []string{},       // note that we are not following referrals at this time
					Controls:  []ldap.Control{}, // TODO are there any response controls that we need to be able to handle?
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultUsernameAttributeValue,
					UID:    testSearchResultUIDAttributeValue,
					Groups: []string{},
				},
			},
		},
		{
			name:     "when the user search filter is already wrapped by parenthesis then it is not wrapped again",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.Filter = "(" + testUserSearchFilter + ")"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultUsernameAttributeValue,
					UID:    testSearchResultUIDAttributeValue,
					Groups: []string{},
				},
			},
		},
		{
			name:     "when the UsernameAttribute is dn and there is a user search filter provided",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.UsernameAttribute = "dn"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{testUserSearchUIDAttribute}
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultDNValue,
					UID:    testSearchResultUIDAttributeValue,
					Groups: []string{},
				},
			},
		},
		{
			name:     "when the UIDAttribute is dn",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.UIDAttribute = "dn"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{testUserSearchUsernameAttribute}
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultUsernameAttributeValue,
					UID:    testSearchResultDNValue,
					Groups: []string{},
				},
			},
		},
		{
			name:     "when Filter is blank it derives a search filter from the UsernameAttribute",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.Filter = ""
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(func(r *ldap.SearchRequest) {
					r.Filter = "(" + testUserSearchUsernameAttribute + "=" + testUpstreamUsername + ")"
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultUsernameAttributeValue,
					UID:    testSearchResultUIDAttributeValue,
					Groups: []string{},
				},
			},
		},
		{
			name:           "when the username has special LDAP search filter characters then they must be properly escaped in the search filter",
			username:       `a&b|c(d)e\f*g`,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(func(r *ldap.SearchRequest) {
					r.Filter = fmt.Sprintf("(some-filter=%s-and-more-filter=%s)", `a&b|c\28d\29e\5cf\2ag`, `a&b|c\28d\29e\5cf\2ag`)
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testSearchResultUsernameAttributeValue,
					UID:    testSearchResultUIDAttributeValue,
					Groups: []string{},
				},
			},
		},
		{
			name:           "when dial fails",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			dialError:      errors.New("some dial error"),
			wantError:      fmt.Sprintf(`error dialing host "%s": some dial error`, testHost),
		},
		{
			name:     "when the UsernameAttribute is dn and there is not a user search filter provided",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = ""
			}),
			wantToSkipDial: true,
			wantError:      `must specify UserSearch Filter when UserSearch UsernameAttribute is "dn"`,
		},
		{
			name:           "when binding as the bind user returns an error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Return(errors.New("some bind error")).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`error binding as "%s" before user search: some bind error`, testBindUsername),
		},
		{
			name:           "when searching for the user returns an error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(nil, errors.New("some search error")).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`error searching for user "%s": some search error`, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns no results",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantUnauthenticated: true,
		},
		{
			name:           "when searching for the user returns multiple results",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: testSearchResultDNValue},
						{DN: "some-other-dn"},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`searching for user "%s" resulted in 2 search results, but expected 1 result`, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user without a DN",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: ""},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`searching for user "%s" resulted in search result without DN`, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user without an expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found 0 values for attribute "%s" while searching for user "%s", but expected 1 result`, testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user with too many values for the expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{
									testSearchResultUsernameAttributeValue,
									"unexpected-additional-value",
								}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found 2 values for attribute "%s" while searching for user "%s", but expected 1 result`, testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user with an empty value for the expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{""}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`, testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user without an expected UID attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found 0 values for attribute "%s" while searching for user "%s", but expected 1 result`, testUserSearchUIDAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user with too many values for the expected UID attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{
									testSearchResultUIDAttributeValue,
									"unexpected-additional-value",
								}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found 2 values for attribute "%s" while searching for user "%s", but expected 1 result`, testUserSearchUIDAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the user returns a user with an empty value for the expected UID attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{""}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`, testUserSearchUIDAttribute, testUpstreamUsername),
		},
		{
			name:           "when binding as the found user returns an error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Return(errors.New("some bind error")).Times(1)
			},
			skipDryRunAuthenticateUser: true,
			wantError:                  fmt.Sprintf(`error binding for user "%s" using provided password against DN "%s": some bind error`, testUpstreamUsername, testSearchResultDNValue),
		},
		{
			name:           "when binding as the found user returns a specific invalid credentials error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantUnauthenticated:        true,
			skipDryRunAuthenticateUser: true,
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testSearchResultDNValue, testUpstreamPassword).Return(errors.New(`LDAP Result Code 49 "Invalid Credentials": some bind error`)).Times(1)
			},
		},
		{
			name:                "when no username is specified",
			username:            "",
			password:            testUpstreamPassword,
			providerConfig:      providerConfig(nil),
			wantToSkipDial:      true,
			wantUnauthenticated: true,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			conn := mockldapconn.NewMockConn(ctrl)
			if tt.searchMocks != nil {
				tt.searchMocks(conn)
			}
			if tt.bindEndUserMocks != nil {
				tt.bindEndUserMocks(conn)
			}

			dialWasAttempted := false
			tt.providerConfig.Dialer = LDAPDialerFunc(func(ctx context.Context, hostAndPort string) (Conn, error) {
				dialWasAttempted = true
				require.Equal(t, tt.providerConfig.Host, hostAndPort)
				if tt.dialError != nil {
					return nil, tt.dialError
				}
				return conn, nil
			})

			provider := New(*tt.providerConfig)

			authResponse, authenticated, err := provider.AuthenticateUser(context.Background(), tt.username, tt.password)
			require.Equal(t, !tt.wantToSkipDial, dialWasAttempted)
			switch {
			case tt.wantError != "":
				require.EqualError(t, err, tt.wantError)
				require.False(t, authenticated)
				require.Nil(t, authResponse)
			case tt.wantUnauthenticated:
				require.NoError(t, err)
				require.False(t, authenticated)
				require.Nil(t, authResponse)
			default:
				require.NoError(t, err)
				require.True(t, authenticated)
				require.Equal(t, tt.wantAuthResponse, authResponse)
			}

			// DryRunAuthenticateUser() should have the same behavior as AuthenticateUser() except that it does not bind
			// as the end user to confirm their password. Since it should behave the same, all of the same test cases
			// apply, except for those which are specifically testing what happens when the end user bind fails.
			if tt.skipDryRunAuthenticateUser {
				return // move on to the next test
			}

			// Reset some variables to get ready to call DryRunAuthenticateUser().
			dialWasAttempted = false
			conn = mockldapconn.NewMockConn(ctrl)
			if tt.searchMocks != nil {
				tt.searchMocks(conn)
			}
			// Skip tt.bindEndUserMocks since DryRunAuthenticateUser() never binds as the end user.

			authResponse, authenticated, err = provider.DryRunAuthenticateUser(context.Background(), tt.username)
			require.Equal(t, !tt.wantToSkipDial, dialWasAttempted)
			switch {
			case tt.wantError != "":
				require.EqualError(t, err, tt.wantError)
				require.False(t, authenticated)
				require.Nil(t, authResponse)
			case tt.wantUnauthenticated:
				require.NoError(t, err)
				require.False(t, authenticated)
				require.Nil(t, authResponse)
			default:
				require.NoError(t, err)
				require.True(t, authenticated)
				require.Equal(t, tt.wantAuthResponse, authResponse)
			}
		})
	}
}

func TestTestConnection(t *testing.T) {
	providerConfig := func(editFunc func(p *ProviderConfig)) *ProviderConfig {
		config := &ProviderConfig{
			Name:         "some-provider-name",
			Host:         testHost,
			CABundle:     nil, // this field is only used by the production dialer, which is replaced by a mock for this test
			BindUsername: testBindUsername,
			BindPassword: testBindPassword,
			UserSearch:   UserSearchConfig{}, // not used by TestConnection
		}
		if editFunc != nil {
			editFunc(config)
		}
		return config
	}

	tests := []struct {
		name           string
		providerConfig *ProviderConfig
		setupMocks     func(conn *mockldapconn.MockConn)
		dialError      error
		wantError      string
		wantToSkipDial bool
	}{
		{
			name:           "happy path",
			providerConfig: providerConfig(nil),
			setupMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Close().Times(1)
			},
		},
		{
			name:           "when dial fails",
			providerConfig: providerConfig(nil),
			dialError:      errors.New("some dial error"),
			wantError:      fmt.Sprintf(`error dialing host "%s": some dial error`, testHost),
		},
		{
			name:           "when binding as the bind user returns an error",
			providerConfig: providerConfig(nil),
			setupMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Return(errors.New("some bind error")).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`error binding as "%s": some bind error`, testBindUsername),
		},
		{
			name: "when the config is invalid",
			providerConfig: providerConfig(func(p *ProviderConfig) {
				// This particular combination of options is not allowed.
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = ""
			}),
			wantToSkipDial: true,
			wantError:      `must specify UserSearch Filter when UserSearch UsernameAttribute is "dn"`,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			conn := mockldapconn.NewMockConn(ctrl)
			if tt.setupMocks != nil {
				tt.setupMocks(conn)
			}

			dialWasAttempted := false
			tt.providerConfig.Dialer = LDAPDialerFunc(func(ctx context.Context, hostAndPort string) (Conn, error) {
				dialWasAttempted = true
				require.Equal(t, tt.providerConfig.Host, hostAndPort)
				if tt.dialError != nil {
					return nil, tt.dialError
				}
				return conn, nil
			})

			provider := New(*tt.providerConfig)
			err := provider.TestConnection(context.Background())

			require.Equal(t, !tt.wantToSkipDial, dialWasAttempted)

			switch {
			case tt.wantError != "":
				require.EqualError(t, err, tt.wantError)
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	c := ProviderConfig{
		Name:         "original-provider-name",
		Host:         testHost,
		CABundle:     []byte("some-ca-bundle"),
		BindUsername: testBindUsername,
		BindPassword: testBindPassword,
		UserSearch: UserSearchConfig{
			Base:              testUserSearchBase,
			Filter:            testUserSearchFilter,
			UsernameAttribute: testUserSearchUsernameAttribute,
			UIDAttribute:      testUserSearchUIDAttribute,
		},
	}
	p := New(c)
	require.Equal(t, c, p.c)
	require.Equal(t, c, p.GetConfig())

	// The original config can be changed without impacting the provider, since the provider made a copy of the config.
	c.Name = "changed-name"
	require.Equal(t, "original-provider-name", p.c.Name)

	// The return value of GetConfig can be modified without impacting the provider, since it is a copy of the config.
	returnedConfig := p.GetConfig()
	returnedConfig.Name = "changed-name"
	require.Equal(t, "original-provider-name", p.c.Name)
}

func TestGetURL(t *testing.T) {
	require.Equal(t, "ldaps://ldap.example.com:1234", New(ProviderConfig{Host: "ldap.example.com:1234"}).GetURL())
	require.Equal(t, "ldaps://ldap.example.com", New(ProviderConfig{Host: "ldap.example.com"}).GetURL())
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
			provider := New(ProviderConfig{
				Host:     test.host,
				CABundle: test.caBundle,
				Dialer:   nil, // this test is for the default (production) dialer
			})
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

				// Indirectly checking that the Dialer method constructed the ldap.Conn with isTLS set to true,
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
