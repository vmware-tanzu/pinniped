// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamad

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/mocks/mockldapconn"
	"go.pinniped.dev/internal/testutil"
)

const (
	testHost                                      = "activedirectory.example.com:8443"
	testBindUsername                              = "cn=some-bind-username,dc=pinniped,dc=dev"
	testBindPassword                              = "some-bind-password"
	testUpstreamUsername                          = "some-upstream-username"
	testUpstreamPassword                          = "some-upstream-password"
	testUserSearchBase                            = "some-upstream-user-base-dn"
	testGroupSearchBase                           = "some-upstream-group-base-dn"
	testUserSearchFilter                          = "some-user-filter={}-and-more-filter={}"
	testGroupSearchFilter                         = "some-group-filter={}-and-more-filter={}"
	testUserSearchUsernameAttribute               = "some-upstream-username-attribute"
	testUserSearchUIDAttribute                    = "objectGUID"
	testGroupSearchGroupNameAttribute             = "some-upstream-group-name-attribute"
	testUserSearchResultDNValue                   = "some-upstream-user-dn"
	testGroupSearchResultDNValue1                 = "some-upstream-group-dn1"
	testGroupSearchResultDNValue2                 = "some-upstream-group-dn2"
	testUserSearchResultUsernameAttributeValue    = "some-upstream-username-value"
	testUserSearchResultUIDAttributeValue         = "Ej5FZ+ibEtOkVkJmFBdAAA==" // this is base64 encoded 123e4567-e89b-12d3-a456-426614174000
	testGroupSearchResultGroupNameAttributeValue1 = "some-upstream-group-name-value1"
	testGroupSearchResultGroupNameAttributeValue2 = "some-upstream-group-name-value2"

	expectedGroupSearchPageSize = uint32(250)
)

var (
	testUserSearchFilterInterpolated  = fmt.Sprintf("(some-user-filter=%s-and-more-filter=%s)", testUpstreamUsername, testUpstreamUsername)
	testGroupSearchFilterInterpolated = fmt.Sprintf("(some-group-filter=%s-and-more-filter=%s)", testUserSearchResultDNValue, testUserSearchResultDNValue)
)

func TestEndUserAuthentication(t *testing.T) {
	providerConfig := func(editFunc func(p *ProviderConfig)) *ProviderConfig {
		config := &ProviderConfig{
			Name:               "some-provider-name",
			Host:               testHost,
			CABundle:           nil, // this field is only used by the production dialer, which is replaced by a mock for this test
			ConnectionProtocol: TLS,
			BindUsername:       testBindUsername,
			BindPassword:       testBindPassword,
			UserSearch: UserSearchConfig{
				Base:              testUserSearchBase,
				Filter:            testUserSearchFilter,
				UsernameAttribute: testUserSearchUsernameAttribute,
				UIDAttribute:      testUserSearchUIDAttribute,
			},
			GroupSearch: GroupSearchConfig{
				Base:               testGroupSearchBase,
				Filter:             testGroupSearchFilter,
				GroupNameAttribute: testGroupSearchGroupNameAttribute,
			},
		}
		if editFunc != nil {
			editFunc(config)
		}
		return config
	}

	expectedUserSearch := func(editFunc func(r *ldap.SearchRequest)) *ldap.SearchRequest {
		request := &ldap.SearchRequest{
			BaseDN:       testUserSearchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    2,
			TimeLimit:    90,
			TypesOnly:    false,
			Filter:       testUserSearchFilterInterpolated,
			Attributes:   []string{testUserSearchUsernameAttribute, testUserSearchUIDAttribute},
			Controls:     nil, // don't need paging because we set the SizeLimit so small
		}
		if editFunc != nil {
			editFunc(request)
		}
		return request
	}

	expectedGroupSearch := func(editFunc func(r *ldap.SearchRequest)) *ldap.SearchRequest {
		request := &ldap.SearchRequest{
			BaseDN:       testGroupSearchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    0, // unlimited size because we will search with paging
			TimeLimit:    90,
			TypesOnly:    false,
			Filter:       testGroupSearchFilterInterpolated,
			Attributes:   []string{testGroupSearchGroupNameAttribute},
			Controls:     nil, // nil because ldap.SearchWithPaging() will set the appropriate controls for us
		}
		if editFunc != nil {
			editFunc(request)
		}
		return request
	}

	exampleUserSearchResult := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: testUserSearchResultDNValue,
				Attributes: []*ldap.EntryAttribute{
					ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testUserSearchResultUsernameAttributeValue}),
					ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
				},
			},
		},
	}

	exampleGroupSearchResult := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: testGroupSearchResultDNValue1,
				Attributes: []*ldap.EntryAttribute{
					ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue1}),
				},
			},
			{
				DN: testGroupSearchResultDNValue2,
				Attributes: []*ldap.EntryAttribute{
					ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue2}),
				},
			},
		},
		Referrals: []string{}, // note that we are not following referrals at this time
		Controls:  []ldap.Control{},
	}

	// The auth response which matches the exampleUserSearchResult and exampleGroupSearchResult.
	expectedAuthResponse := func(editFunc func(r *user.DefaultInfo)) *authenticator.Response {
		u := &user.DefaultInfo{
			Name:   testUserSearchResultUsernameAttributeValue,
			UID:    "123e4567-e89b-12d3-a456-426614174000",
			Groups: []string{testGroupSearchResultGroupNameAttributeValue1, testGroupSearchResultGroupNameAttributeValue2},
		}
		if editFunc != nil {
			editFunc(u)
		}
		return &authenticator.Response{User: u}
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "default as much as possible",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: &ProviderConfig{
				Name:               "some-provider-name",
				Host:               testHost,
				CABundle:           nil, // this field is only used by the production dialer, which is replaced by a mock for this test
				ConnectionProtocol: TLS,
				BindUsername:       testBindUsername,
				BindPassword:       testBindPassword,
				GroupSearch: GroupSearchConfig{
					Base:               testGroupSearchBase,
					Filter:             testGroupSearchFilter,
					GroupNameAttribute: testGroupSearchGroupNameAttribute,
				},
			},
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Filter = "(" + sAMAccountNameAttributeName + "=" + testUpstreamUsername + ")"
					r.Attributes = []string{sAMAccountNameAttributeName, testUserSearchUIDAttribute}
					r.BaseDN = "dc=activedirectory,dc=example,dc=com"
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(sAMAccountNameAttributeName, []string{testUserSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "when the group search filter is already wrapped by parenthesis then it is not wrapped again",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.Filter = "(" + testGroupSearchFilter + ")"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "when the group search base is empty then skip the group search entirely",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.Base = "" // this configuration means that the user does not want group search to happen
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(func(r *user.DefaultInfo) {
				r.Groups = []string{}
			}),
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
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{testUserSearchUIDAttribute}
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(func(r *user.DefaultInfo) {
				r.Name = testUserSearchResultDNValue
			}),
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
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{testUserSearchUsernameAttribute}
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testUserSearchResultUsernameAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(func(r *user.DefaultInfo) {
				r.UID = base64.RawURLEncoding.EncodeToString([]byte(testUserSearchResultDNValue))
			}),
		},
		{
			name:     "when the GroupNameAttribute is empty then it defaults to dn",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "" // blank means to use dn
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{}
				}), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(func(r *user.DefaultInfo) {
				r.Groups = []string{testGroupSearchResultDNValue1, testGroupSearchResultDNValue2}
			}),
		},
		{
			name:     "when the GroupNameAttribute is dn",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "dn"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{}
				}), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(func(r *user.DefaultInfo) {
				r.Groups = []string{testGroupSearchResultDNValue1, testGroupSearchResultDNValue2}
			}),
		},
		{
			name:     "when the GroupNameAttribute is cn",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "cn"
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(func(r *ldap.SearchRequest) {
					r.Attributes = []string{"cn"}
				}), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute("cn", []string{testGroupSearchResultGroupNameAttributeValue1}),
								},
							},
							{
								DN: testGroupSearchResultDNValue2,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute("cn", []string{testGroupSearchResultGroupNameAttributeValue2}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "when user search Filter is blank it derives a search filter from the UsernameAttribute",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.Filter = ""
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Filter = "(" + testUserSearchUsernameAttribute + "=" + testUpstreamUsername + ")"
				})).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "when user search Filter and user attribute is blank it defaults to sAMAccountName={}",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.UserSearch.Filter = ""
				p.UserSearch.UsernameAttribute = ""
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Filter = "(" + sAMAccountNameAttributeName + "=" + testUpstreamUsername + ")"
					r.Attributes = []string{sAMAccountNameAttributeName, testUserSearchUIDAttribute}
				})).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(sAMAccountNameAttributeName, []string{testUserSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:     "when group search Filter is blank it uses a default search filter of member={}",
			username: testUpstreamUsername,
			password: testUpstreamPassword,
			providerConfig: providerConfig(func(p *ProviderConfig) {
				p.GroupSearch.Filter = ""
			}),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(func(r *ldap.SearchRequest) {
					r.Filter = "(member=" + testUserSearchResultDNValue + ")"
				}), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:           "when the username has special LDAP search filter characters then they must be properly escaped in the search filter, because the username is end-user input",
			username:       `a&b|c(d)e\f*g`,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(func(r *ldap.SearchRequest) {
					r.Filter = fmt.Sprintf("(some-user-filter=%s-and-more-filter=%s)", `a&b|c\28d\29e\5cf\2ag`, `a&b|c\28d\29e\5cf\2ag`)
				})).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: expectedAuthResponse(nil),
		},
		{
			name:           "group names are sorted to make the result more stable/predictable",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{"c"}),
								},
							},
							{
								DN: testGroupSearchResultDNValue2,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{"a"}),
								},
							},
							{
								DN: testGroupSearchResultDNValue2,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{"b"}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Times(1)
			},
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   testUserSearchResultUsernameAttributeValue,
					UID:    "123e4567-e89b-12d3-a456-426614174000",
					Groups: []string{"a", "b", "c"},
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(nil, errors.New("some user search error")).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: `error searching for user: some user search error`,
		},
		{
			name:           "when searching for the user's groups returns an error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(nil, errors.New("some group search error")).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`error searching for group memberships for user with DN "%s": some group search error`, testUserSearchResultDNValue),
		},
		{
			name:           "when searching for the user returns no results",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: testUserSearchResultDNValue},
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: ""},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(`searching for user "%s" resulted in search result without DN`, testUpstreamUsername),
		},
		{
			name:           "when searching for the user's groups returns a group without a DN",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue1}),
								},
							},
							{
								DN: "",
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue2}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`searching for group memberships for user with DN "%s" resulted in search result without DN`,
				testUserSearchResultDNValue),
		},
		{
			name:           "when searching for the user returns a user without an expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`found 0 values for attribute "%s" while searching for user "%s", but expected 1 result`,
				testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the group memberships returns a group without an expected group name attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue1}),
								},
							},
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute("unrelated attribute", []string{"anything"}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`error searching for group memberships for user with DN "%s": found 0 values for attribute "%s" while searching for user "%s", but expected 1 result`,
				testUserSearchResultDNValue, testGroupSearchGroupNameAttribute, testUserSearchResultDNValue),
		},
		{
			name:           "when searching for the user returns a user with too many values for the expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{
									testUserSearchResultUsernameAttributeValue,
									"unexpected-additional-value",
								}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`found 2 values for attribute "%s" while searching for user "%s", but expected 1 result`,
				testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the group memberships returns a group with too many values for the expected group name attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue1}),
								},
							},
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{
										testGroupSearchResultGroupNameAttributeValue1,
										"unexpected-additional-value",
									}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`error searching for group memberships for user with DN "%s": found 2 values for attribute "%s" while searching for user "%s", but expected 1 result`,
				testUserSearchResultDNValue, testGroupSearchGroupNameAttribute, testUserSearchResultDNValue),
		},
		{
			name:           "when searching for the user returns a user with an empty value for the expected username attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{""}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{testUserSearchResultUIDAttributeValue}),
							},
						},
					},
				}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`,
				testUserSearchUsernameAttribute, testUpstreamUsername),
		},
		{
			name:           "when searching for the group memberships returns a group with an empty value for for the expected group name attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(&ldap.SearchResult{
						Entries: []*ldap.Entry{
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{testGroupSearchResultGroupNameAttributeValue1}),
								},
							},
							{
								DN: testGroupSearchResultDNValue1,
								Attributes: []*ldap.EntryAttribute{
									ldap.NewEntryAttribute(testGroupSearchGroupNameAttribute, []string{""}),
								},
							},
						},
						Referrals: []string{}, // note that we are not following referrals at this time
						Controls:  []ldap.Control{},
					}, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantError: fmt.Sprintf(
				`error searching for group memberships for user with DN "%s": found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`,
				testUserSearchResultDNValue, testGroupSearchGroupNameAttribute, testUserSearchResultDNValue),
		},
		{
			name:           "when searching for the user returns a user without an expected UID attribute",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testUserSearchResultUsernameAttributeValue}),
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testUserSearchResultUsernameAttributeValue}),
								ldap.NewEntryAttribute(testUserSearchUIDAttribute, []string{
									testUserSearchResultUIDAttributeValue,
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(&ldap.SearchResult{
					Entries: []*ldap.Entry{
						{
							DN: testUserSearchResultDNValue,
							Attributes: []*ldap.EntryAttribute{
								ldap.NewEntryAttribute(testUserSearchUsernameAttribute, []string{testUserSearchResultUsernameAttributeValue}),
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
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Return(errors.New("some bind error")).Times(1)
			},
			skipDryRunAuthenticateUser: true,
			wantError:                  fmt.Sprintf(`error binding for user "%s" using provided password against DN "%s": some bind error`, testUpstreamUsername, testUserSearchResultDNValue),
		},
		{
			name:           "when binding as the found user returns a specific invalid credentials error",
			username:       testUpstreamUsername,
			password:       testUpstreamPassword,
			providerConfig: providerConfig(nil),
			searchMocks: func(conn *mockldapconn.MockConn) {
				conn.EXPECT().Bind(testBindUsername, testBindPassword).Times(1)
				conn.EXPECT().Search(expectedUserSearch(nil)).Return(exampleUserSearchResult, nil).Times(1)
				conn.EXPECT().SearchWithPaging(expectedGroupSearch(nil), expectedGroupSearchPageSize).
					Return(exampleGroupSearchResult, nil).Times(1)
				conn.EXPECT().Close().Times(1)
			},
			wantUnauthenticated:        true,
			skipDryRunAuthenticateUser: true,
			bindEndUserMocks: func(conn *mockldapconn.MockConn) {
				err := &ldap.Error{
					Err:        errors.New("some bind error"),
					ResultCode: ldap.LDAPResultInvalidCredentials,
				}
				conn.EXPECT().Bind(testUserSearchResultDNValue, testUpstreamPassword).Return(err).Times(1)
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
			tt.providerConfig.Dialer = LDAPDialerFunc(func(ctx context.Context, addr endpointaddr.HostPort) (Conn, error) {
				dialWasAttempted = true
				require.Equal(t, tt.providerConfig.Host, addr.Endpoint())
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
			Name:               "some-provider-name",
			Host:               testHost,
			CABundle:           nil, // this field is only used by the production dialer, which is replaced by a mock for this test
			ConnectionProtocol: TLS,
			BindUsername:       testBindUsername,
			BindPassword:       testBindPassword,
			UserSearch:         UserSearchConfig{}, // not used by TestConnection
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
			tt.providerConfig.Dialer = LDAPDialerFunc(func(ctx context.Context, addr endpointaddr.HostPort) (Conn, error) {
				dialWasAttempted = true
				require.Equal(t, tt.providerConfig.Host, addr.Endpoint())
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
	require.Equal(t,
		"ldaps://ldap.example.com:1234?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev",
		New(ProviderConfig{
			Host:       "ldap.example.com:1234",
			UserSearch: UserSearchConfig{Base: "ou=users,dc=pinniped,dc=dev"},
		}).GetURL().String())

	require.Equal(t,
		"ldaps://ldap.example.com?base=ou%3Dusers%2Cdc%3Dpinniped%2Cdc%3Ddev",
		New(ProviderConfig{
			Host:       "ldap.example.com",
			UserSearch: UserSearchConfig{Base: "ou=users,dc=pinniped,dc=dev"},
		}).GetURL().String())
}

// Testing of host parsing, TLS negotiation, and CA bundle, etc. for the production code's dialer.
func TestRealTLSDialing(t *testing.T) {
	testServerCABundle, testServerURL := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	parsedURL, err := url.Parse(testServerURL)
	require.NoError(t, err)
	testServerHostAndPort := parsedURL.Host

	caForTestServerWithBadCertName, err := certauthority.New("Test CA", time.Hour)
	require.NoError(t, err)
	wrongIP := net.ParseIP("10.2.3.4")
	cert, err := caForTestServerWithBadCertName.IssueServerCert([]string{"wrong-dns-name"}, []net.IP{wrongIP}, time.Hour)
	require.NoError(t, err)
	testServerWithBadCertNameAddr := testutil.TLSTestServerWithCert(t, func(w http.ResponseWriter, r *http.Request) {}, cert)

	unusedPortGrabbingListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	recentlyClaimedHostAndPort := unusedPortGrabbingListener.Addr().String()
	require.NoError(t, unusedPortGrabbingListener.Close())

	alreadyCancelledContext, cancelFunc := context.WithCancel(context.Background())
	cancelFunc() // cancel it immediately

	tests := []struct {
		name      string
		host      string
		connProto LDAPConnectionProtocol
		caBundle  []byte
		context   context.Context
		wantError string
	}{
		{
			name:      "happy path",
			host:      testServerHostAndPort,
			caBundle:  []byte(testServerCABundle),
			connProto: TLS,
			context:   context.Background(),
		},
		{
			name:      "server cert name does not match the address to which the client connected",
			host:      testServerWithBadCertNameAddr,
			caBundle:  caForTestServerWithBadCertName.Bundle(),
			connProto: TLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": x509: certificate is valid for 10.2.3.4, not 127.0.0.1`,
		},
		{
			name:      "invalid CA bundle with TLS",
			host:      testServerHostAndPort,
			caBundle:  []byte("not a ca bundle"),
			connProto: TLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": could not parse CA bundle`,
		},
		{
			name:      "invalid CA bundle with StartTLS",
			host:      testServerHostAndPort,
			caBundle:  []byte("not a ca bundle"),
			connProto: StartTLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": could not parse CA bundle`,
		},
		{
			name:      "invalid host with TLS",
			host:      "this:is:not:a:valid:hostname",
			caBundle:  []byte(testServerCABundle),
			connProto: TLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": host "this:is:not:a:valid:hostname" is not a valid hostname or IP address`,
		},
		{
			name:      "invalid host with StartTLS",
			host:      "this:is:not:a:valid:hostname",
			caBundle:  []byte(testServerCABundle),
			connProto: StartTLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": host "this:is:not:a:valid:hostname" is not a valid hostname or IP address`,
		},
		{
			name:      "missing CA bundle when it is required because the host is not using a trusted CA",
			host:      testServerHostAndPort,
			caBundle:  nil,
			connProto: TLS,
			context:   context.Background(),
			wantError: `LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority`,
		},
		{
			name: "cannot connect to host",
			// This is assuming that this port was not reclaimed by another app since the test setup ran. Seems safe enough.
			host:      recentlyClaimedHostAndPort,
			caBundle:  []byte(testServerCABundle),
			connProto: TLS,
			context:   context.Background(),
			wantError: fmt.Sprintf(`LDAP Result Code 200 "Network Error": dial tcp %s: connect: connection refused`, recentlyClaimedHostAndPort),
		},
		{
			name:      "pays attention to the passed context",
			host:      testServerHostAndPort,
			caBundle:  []byte(testServerCABundle),
			connProto: TLS,
			context:   alreadyCancelledContext,
			wantError: fmt.Sprintf(`LDAP Result Code 200 "Network Error": dial tcp %s: operation was canceled`, testServerHostAndPort),
		},
		{
			name:      "unsupported connection protocol",
			host:      testServerHostAndPort,
			caBundle:  []byte(testServerCABundle),
			connProto: "bad usage of this type",
			context:   alreadyCancelledContext,
			wantError: `LDAP Result Code 200 "Network Error": did not specify valid ConnectionProtocol`,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			provider := New(ProviderConfig{
				Host:               tt.host,
				CABundle:           tt.caBundle,
				ConnectionProtocol: tt.connProto,
				Dialer:             nil, // this test is for the default (production) TLS dialer
			})
			conn, err := provider.dial(tt.context)
			if conn != nil {
				defer conn.Close()
			}
			if tt.wantError != "" {
				require.Nil(t, conn)
				require.EqualError(t, err, tt.wantError)
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
