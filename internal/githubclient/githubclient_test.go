// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubclient

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v63/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/cert"

	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/setutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestNewGitHubClient(t *testing.T) {
	t.Parallel()

	t.Run("rejects nil http client", func(t *testing.T) {
		_, err := NewGitHubClient(nil, "https://api.github.com/", "")
		require.EqualError(t, err, "unable to build new github client: httpClient cannot be nil")
	})

	tests := []struct {
		name        string
		apiBaseURL  string
		token       string
		wantBaseURL string
		wantErr     string
	}{
		{
			name:        "happy path with https://api.github.com/",
			apiBaseURL:  "https://api.github.com/",
			token:       "some-token",
			wantBaseURL: "https://api.github.com/",
		},
		{
			name:        "adds trailing slash to path for https://api.github.com",
			apiBaseURL:  "https://api.github.com",
			token:       "other-token",
			wantBaseURL: "https://api.github.com/",
		},
		{
			name:        "adds trailing slash to path for Enterprise URL https://fake.enterprise.tld/api/v3",
			apiBaseURL:  "https://fake.enterprise.tld/api/v3",
			token:       "some-enterprise-token",
			wantBaseURL: "https://fake.enterprise.tld/api/v3/",
		},
		{
			name:       "rejects apiBaseURL without https:// scheme",
			apiBaseURL: "scp://github.com",
			token:      "some-token",
			wantErr:    `unable to build new github client: apiBaseURL must use "https" protocol, found "scp" instead`,
		},
		{
			name:       "rejects apiBaseURL with empty scheme",
			apiBaseURL: "github.com",
			token:      "some-token",
			wantErr:    `unable to build new github client: apiBaseURL must use "https" protocol, found "" instead`,
		},
		{
			name:       "rejects empty token",
			apiBaseURL: "https://api.github.com/",
			wantErr:    "unable to build new github client: token cannot be empty string",
		},
		{
			name:       "returns errors from url.Parse",
			apiBaseURL: "https:// example.com",
			token:      "some-token",
			wantErr:    `unable to build new github client: parse "https:// example.com": invalid character " " in host name`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			called := false
			testServer, testServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Len(t, r.Header["Authorization"], 1)
				require.Equal(t, "Bearer "+test.token, r.Header.Get("Authorization"))
				called = true
			}), nil)

			t.Cleanup(func() {
				require.True(t, (test.wantErr == "" && called) || (test.wantErr != "" && !called))
			})

			pool, err := cert.NewPoolFromBytes(testServerCA)
			require.NoError(t, err)

			httpClient := phttp.Default(pool)

			actualI, err := NewGitHubClient(httpClient, test.apiBaseURL, test.token)

			if test.wantErr != "" {
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)

				require.NotNil(t, actualI)
				actual, ok := actualI.(*githubClient)
				require.True(t, ok)
				require.NotNil(t, actual.client.BaseURL)
				require.Equal(t, test.wantBaseURL, actual.client.BaseURL.String())

				// Force the githubClient's httpClient roundTrippers to run and add the Authorization header

				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testServer.URL, nil)
				require.NoError(t, err)

				_, err = actual.client.Client().Do(req) //nolint:bodyclose
				require.NoError(t, err)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		httpClient   *http.Client
		token        string
		ctx          context.Context
		wantErr      string
		wantUserInfo UserInfo
	}{
		{
			name: "happy path",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					github.User{
						Login: github.String("some-username"),
						ID:    github.Int64(12345678),
					},
				),
			),
			token: "some-token",
			wantUserInfo: UserInfo{
				Login: "some-username",
				ID:    "12345678",
			},
		},
		{
			name: "the token is added in the Authorization header",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUser,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						require.Len(t, r.Header["Authorization"], 1)
						require.Equal(t, "Bearer does-this-token-work", r.Header.Get("Authorization"))
						_, err := w.Write([]byte(`{"login":"some-authenticated-username","id":999888}`))
						require.NoError(t, err)
					}),
				),
			),
			token: "does-this-token-work",
			wantUserInfo: UserInfo{
				Login: "some-authenticated-username",
				ID:    "999888",
			},
		},
		{
			name: "handles missing login",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					github.User{
						ID: github.Int64(12345678),
					},
				),
			),
			token:   "does-this-token-work",
			wantErr: `error fetching authenticated user: the "login" attribute is missing`,
		},
		{
			name: "handles missing ID",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					github.User{
						Login: github.String("some-username"),
					},
				),
			),
			token:   "does-this-token-work",
			wantErr: `error fetching authenticated user: the "id" attribute is missing`,
		},
		{
			name:       "passes the context parameter into the API call",
			token:      "some-token",
			httpClient: mock.NewMockedHTTPClient(),
			ctx: func() context.Context {
				canceledCtx, cancel := context.WithCancel(context.Background())
				cancel()
				return canceledCtx
			}(),
			wantErr: "error fetching authenticated user: context canceled",
		},
		{
			name: "returns errors from the API",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUser,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mock.WriteError(
							w,
							http.StatusInternalServerError,
							"internal server error from the server",
						)
					}),
				),
			),
			token:   "some-token",
			wantErr: "error fetching authenticated user: GET {SERVER_URL}/user: 500 internal server error from the server []",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			githubClient := &githubClient{
				client: github.NewClient(test.httpClient).WithAuthToken(test.token),
			}

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx
			}

			actual, err := githubClient.GetUserInfo(ctx)
			if test.wantErr != "" {
				rt, ok := test.httpClient.Transport.(*mock.EnforceHostRoundTripper)
				require.True(t, ok)
				test.wantErr = strings.ReplaceAll(test.wantErr, "{SERVER_URL}", rt.Host)
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, actual)
				require.Equal(t, test.wantUserInfo, *actual)
			}
		})
	}
}

func TestGetOrgMembership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		httpClient *http.Client
		token      string
		ctx        context.Context
		wantErr    string
		wantOrgs   []string
	}{
		{
			name: "happy path",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserOrgs,
					[]github.Organization{
						{Login: github.String("org1")},
						{Login: github.String("org2")},
						{Login: github.String("org3")},
					},
				),
			),
			token:    "some-token",
			wantOrgs: []string{"org1", "org2", "org3"},
		},
		{
			name: "happy path with pagination",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchPages(
					mock.GetUserOrgs,
					[]github.Organization{
						{Login: github.String("page1-org1")},
						{Login: github.String("page1-org2")},
						{Login: github.String("page1-org3")},
					},
					[]github.Organization{
						{Login: github.String("page2-org1")},
						{Login: github.String("page2-org2")},
						{Login: github.String("page2-org3")},
					},
				),
			),
			token:    "some-token",
			wantOrgs: []string{"page1-org1", "page1-org2", "page1-org3", "page2-org1", "page2-org2", "page2-org3"},
		},
		{
			name: "the token is added in the Authorization header",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUserOrgs,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						require.Len(t, r.Header["Authorization"], 1)
						require.Equal(t, "Bearer does-this-token-work", r.Header.Get("Authorization"))
						_, err := w.Write([]byte(`[{"login":"some-org-to-which-the-authenticated-user-belongs"}]`))
						require.NoError(t, err)
					}),
				),
			),
			token:    "does-this-token-work",
			wantOrgs: []string{"some-org-to-which-the-authenticated-user-belongs"},
		},
		{
			name: "errors when a Login field is empty",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserOrgs,
					[]github.Organization{
						{Login: github.String("page1-org1")},
						{Login: nil},
						{Login: github.String("page1-org3")},
					},
				),
			),
			token:   "some-token",
			wantErr: `error fetching organizations for authenticated user: one or more organizations is missing the "login" attribute`,
		},
		{
			name:       "passes the context parameter into the API call",
			token:      "some-token",
			httpClient: mock.NewMockedHTTPClient(),
			ctx: func() context.Context {
				canceledCtx, cancel := context.WithCancel(context.Background())
				cancel()
				return canceledCtx
			}(),
			wantErr: "error fetching organizations for authenticated user: context canceled",
		},
		{
			name: "returns errors from the API",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUserOrgs,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mock.WriteError(
							w,
							http.StatusFailedDependency,
							"some random client error",
						)
					}),
				),
			),
			token:   "some-token",
			wantErr: "error fetching organizations for authenticated user: GET {SERVER_URL}/user/orgs?per_page=100: 424 some random client error []",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			githubClient := &githubClient{
				client: github.NewClient(test.httpClient).WithAuthToken(test.token),
			}

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx
			}

			actual, err := githubClient.GetOrgMembership(ctx)
			if test.wantErr != "" {
				rt, ok := test.httpClient.Transport.(*mock.EnforceHostRoundTripper)
				require.True(t, ok)
				test.wantErr = strings.ReplaceAll(test.wantErr, "{SERVER_URL}", rt.Host)
				require.EqualError(t, err, test.wantErr)
				return
			}

			require.NotNil(t, actual)
			require.ElementsMatch(t, test.wantOrgs, actual)
		})
	}
}

func TestGetTeamMembership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		httpClient           *http.Client
		token                string
		ctx                  context.Context
		allowedOrganizations *setutil.CaseInsensitiveSet
		wantErr              string
		wantTeams            []TeamInfo
	}{
		{
			name: "happy path",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("orgAlpha-team1-name"),
							Slug: github.String("orgAlpha-team1-slug"),
							Organization: &github.Organization{
								Login: github.String("alpha"),
							},
						},
						{
							Name: github.String("orgAlpha-team2-name"),
							Slug: github.String("orgAlpha-team2-slug"),
							Organization: &github.Organization{
								Login: github.String("alpha"),
							},
						},
						{
							Name: github.String("orgAlpha-team3-name"),
							Slug: github.String("orgAlpha-team3-slug"),
							Organization: &github.Organization{
								Login: github.String("alpha"),
							},
						},
						{
							Name: github.String("orgBeta-team1-name"),
							Slug: github.String("orgBeta-team1-slug"),
							Organization: &github.Organization{
								Login: github.String("beta"),
							},
						},
					},
				),
			),
			token:                "some-token",
			allowedOrganizations: setutil.NewCaseInsensitiveSet("alpha", "beta"),
			wantTeams: []TeamInfo{
				{
					Name: "orgAlpha-team1-name",
					Slug: "orgAlpha-team1-slug",
					Org:  "alpha",
				},
				{
					Name: "orgAlpha-team2-name",
					Slug: "orgAlpha-team2-slug",
					Org:  "alpha",
				},
				{
					Name: "orgAlpha-team3-name",
					Slug: "orgAlpha-team3-slug",
					Org:  "alpha",
				},
				{
					Name: "orgBeta-team1-name",
					Slug: "orgBeta-team1-slug",
					Org:  "beta",
				},
			},
		},
		{
			name: "filters by allowedOrganizations in a case-insensitive way, but preserves case as returned by GitHub API in the result",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("team1-name"),
							Slug: github.String("team1-slug"),
							Organization: &github.Organization{
								Login: github.String("alPhA"),
							},
						},
						{
							Name: github.String("team2-name"),
							Slug: github.String("team2-slug"),
							Organization: &github.Organization{
								Login: github.String("bEtA"),
							},
						},
						{
							Name: github.String("team3-name"),
							Slug: github.String("team3-slug"),
							Organization: &github.Organization{
								Login: github.String("gAmmA"),
							},
						},
					},
				),
			),
			token:                "some-token",
			allowedOrganizations: setutil.NewCaseInsensitiveSet("ALPHA", "gamma"),
			wantTeams: []TeamInfo{
				{
					Name: "team1-name",
					Slug: "team1-slug",
					Org:  "alPhA",
				},
				{
					Name: "team3-name",
					Slug: "team3-slug",
					Org:  "gAmmA",
				},
			},
		},
		{
			name: "when allowedOrganizations is empty, return all teams",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("team1-name"),
							Slug: github.String("team1-slug"),
							Organization: &github.Organization{
								Login: github.String("alpha"),
							},
						},
						{
							Name: github.String("team2-name"),
							Slug: github.String("team2-slug"),
							Organization: &github.Organization{
								Login: github.String("beta"),
							},
						},
						{
							Name: github.String("team3-name"),
							Slug: github.String("team3-slug"),
							Parent: &github.Team{
								Name:         github.String("delta-team-name"),
								Slug:         github.String("delta-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: github.String("gamma"),
							},
						},
					},
				),
			),
			token: "some-token",
			wantTeams: []TeamInfo{
				{
					Name: "team1-name",
					Slug: "team1-slug",
					Org:  "alpha",
				},
				{
					Name: "team2-name",
					Slug: "team2-slug",
					Org:  "beta",
				},
				{
					Name: "delta-team-name",
					Slug: "delta-team-slug",
					Org:  "gamma",
				},
				{
					Name: "team3-name",
					Slug: "team3-slug",
					Org:  "gamma",
				},
			},
		},
		{
			name: "includes parent team in allowed orgs if present",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("team-name-with-parent"),
							Slug: github.String("team-slug-with-parent"),
							Parent: &github.Team{
								Name:         github.String("parent-team-name"),
								Slug:         github.String("parent-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: github.String("org-with-nested-teams"),
							},
						},
						{
							Name: github.String("team-name-with-same-parent-again"),
							Slug: github.String("team-slug-with-same-parent-again"),
							Parent: &github.Team{
								Name:         github.String("parent-team-name"),
								Slug:         github.String("parent-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: github.String("org-with-nested-teams"),
							},
						},
						{
							Name: github.String("parent-team-name"),
							Slug: github.String("parent-team-slug"),
							Organization: &github.Organization{
								Login: github.String("org-with-nested-teams"),
							},
						},
						{
							Name: github.String("team-name-with-parent-from-disallowed-org"),
							Slug: github.String("team-slug-with-parent-from-disallowed-org"),
							Parent: &github.Team{
								Name:         github.String("parent-team-name-from-disallowed-org"),
								Slug:         github.String("parent-team-slug-from-disallowed-org"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: github.String("disallowed-org"),
							},
						},
						{
							Name: github.String("team-name-without-parent"),
							Slug: github.String("team-slug-without-parent"),
							Organization: &github.Organization{
								Login: github.String("beta"),
							},
						},
					},
				),
			),
			token:                "some-token",
			allowedOrganizations: setutil.NewCaseInsensitiveSet("org-with-nested-teams", "beta"),
			wantTeams: []TeamInfo{
				{
					Name: "team-name-without-parent",
					Slug: "team-slug-without-parent",
					Org:  "beta",
				},
				{
					Name: "parent-team-name",
					Slug: "parent-team-slug",
					Org:  "org-with-nested-teams",
				},
				{
					Name: "team-name-with-parent",
					Slug: "team-slug-with-parent",
					Org:  "org-with-nested-teams",
				},
				{
					Name: "team-name-with-same-parent-again",
					Slug: "team-slug-with-same-parent-again",
					Org:  "org-with-nested-teams",
				},
			},
		},
		{
			name: "happy path with pagination",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchPages(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("page1-team-name"),
							Slug: github.String("page1-team-slug"),
							Organization: &github.Organization{
								Login: github.String("page1-org-name"),
							},
						},
					},
					[]github.Team{
						{
							Name: github.String("page2-team-name"),
							Slug: github.String("page2-team-slug"),
							Organization: &github.Organization{
								Login: github.String("page2-org-name"),
							},
						},
					},
				),
			),
			token:                "some-token",
			allowedOrganizations: setutil.NewCaseInsensitiveSet("page1-org-name", "page2-org-name"),
			wantTeams: []TeamInfo{
				{
					Name: "page1-team-name",
					Slug: "page1-team-slug",
					Org:  "page1-org-name",
				},
				{
					Name: "page2-team-name",
					Slug: "page2-team-slug",
					Org:  "page2-org-name",
				},
			},
		},
		{
			name: "missing organization attribute returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("team-name"),
							Slug: github.String("team-slug"),
						},
					},
				),
			),
			wantErr: `error fetching team membership for authenticated user: missing the "organization" attribute for a team`,
		},
		{
			name: "missing organization's login attribute returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name:         github.String("team-name"),
							Slug:         github.String("team-slug"),
							Organization: &github.Organization{},
						},
					},
				),
			),
			wantErr: `error fetching team membership for authenticated user: missing the organization's "login" attribute for a team`,
		},
		{
			name: "missing the name attribute for a team returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Slug: github.String("team-slug"),
							Organization: &github.Organization{
								Login: github.String("some-org"),
							},
						},
					},
				),
			),
			wantErr: `error fetching team membership for authenticated user: the "name" attribute is missing for a team`,
		},
		{
			name: "missing the slug attribute for a team returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: github.String("team-name"),
							Organization: &github.Organization{
								Login: github.String("some-org"),
							},
						},
					},
				),
			),
			wantErr: `error fetching team membership for authenticated user: the "slug" attribute is missing for a team`,
		},
		{
			name: "the token is added in the Authorization header",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUserTeams,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						require.Len(t, r.Header["Authorization"], 1)
						require.Equal(t, "Bearer does-this-token-work", r.Header.Get("Authorization"))
						_, err := w.Write([]byte(`[{"name":"team1-name","slug":"team1-slug","organization":{"login":"org-login"}}]`))
						require.NoError(t, err)
					}),
				),
			),
			token:                "does-this-token-work",
			allowedOrganizations: setutil.NewCaseInsensitiveSet("org-login"),
			wantTeams: []TeamInfo{
				{
					Name: "team1-name",
					Slug: "team1-slug",
					Org:  "org-login",
				},
			},
		},
		{
			name:       "passes the context parameter into the API call",
			token:      "some-token",
			httpClient: mock.NewMockedHTTPClient(),
			ctx: func() context.Context {
				canceledCtx, cancel := context.WithCancel(context.Background())
				cancel()
				return canceledCtx
			}(),
			wantErr: "error fetching team membership for authenticated user: context canceled",
		},
		{
			name: "returns errors from the API",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(
					mock.GetUserTeams,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mock.WriteError(
							w,
							http.StatusFailedDependency,
							"some random client error",
						)
					}),
				),
			),
			token:   "some-token",
			wantErr: "error fetching team membership for authenticated user: GET {SERVER_URL}/user/teams?per_page=100: 424 some random client error []",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			githubClient := &githubClient{
				client: github.NewClient(test.httpClient).WithAuthToken(test.token),
			}

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx
			}

			actual, err := githubClient.GetTeamMembership(ctx, test.allowedOrganizations)
			if test.wantErr != "" {
				rt, ok := test.httpClient.Transport.(*mock.EnforceHostRoundTripper)
				require.True(t, ok)
				test.wantErr = strings.ReplaceAll(test.wantErr, "{SERVER_URL}", rt.Host)
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, actual)
				require.Equal(t, test.wantTeams, actual)
			}
		})
	}
}
