// Copyright 2024-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubclient

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v93/github"
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

			var mu sync.Mutex
			var receivedAuthHeaders [][]string
			testServer, testServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				receivedAuthHeaders = append(receivedAuthHeaders, r.Header.Values("Authorization"))
			}), nil)

			t.Cleanup(func() {
				mu.Lock()
				defer mu.Unlock()
				if test.wantErr != "" {
					require.Empty(t, receivedAuthHeaders)
				}
			})

			testServerURL, err := url.Parse(testServer.URL)
			require.NoError(t, err)

			pool, err := cert.NewPoolFromBytes(testServerCA)
			require.NoError(t, err)

			httpClient := phttp.Default(pool)

			// go-github only adds the Authorization header to requests whose origin matches the client's base URL
			// or upload URL. Redirect every request to the test server below that check, so that requests to the
			// (fake) base URL can be observed.
			originalTransport := httpClient.Transport
			httpClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				req = req.Clone(req.Context())
				req.URL.Scheme = testServerURL.Scheme
				req.URL.Host = testServerURL.Host
				req.Host = ""
				return originalTransport.RoundTrip(req)
			})

			actualI, err := NewGitHubClient(httpClient, test.apiBaseURL, test.token)

			if test.wantErr != "" {
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)

				require.NotNil(t, actualI)
				actual, ok := actualI.(*githubClient)
				require.True(t, ok)
				require.NotNil(t, actual.client)
				require.Equal(t, test.wantBaseURL, actual.client.BaseURL())

				// Force the githubClient's httpClient roundTrippers to run and add the Authorization header
				// for a request to the base URL.
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, actual.client.BaseURL()+"user", nil)
				require.NoError(t, err)

				_, err = actual.client.Client().Do(req) //nolint:bodyclose
				require.NoError(t, err)

				// A request to any other origin should not carry the token (starting in go-github/v93).
				req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, testServer.URL, nil)
				require.NoError(t, err)

				_, err = actual.client.Client().Do(req) //nolint:bodyclose
				require.NoError(t, err)

				mu.Lock()
				defer mu.Unlock()
				// Assert that the first request had the expected auth token and the second request had none.
				require.Equal(t, [][]string{{"Bearer " + test.token}, nil}, receivedAuthHeaders)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		httpClient          *http.Client
		token               string
		ctx                 context.Context
		retryOnUnauthorized bool
		wantErr             string
		wantUserInfo        UserInfo
	}{
		{
			name: "happy path",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUser,
					github.User{
						Login: new("some-username"),
						ID:    new(int64(12345678)),
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
						ID: new(int64(12345678)),
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
						Login: new("some-username"),
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

			c, err := github.NewClient(github.WithHTTPClient(test.httpClient), github.WithAuthToken(test.token))
			require.NoError(t, err)
			githubClient := &githubClient{client: c}

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx
			}

			actual, err := githubClient.GetUserInfo(ctx, test.retryOnUnauthorized)
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

func TestGetUserInfoRetryOnUnauthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		retryOnUnauthorized bool
		retryDelay          time.Duration // zero means no artificial delay
		ctxTimeout          time.Duration // zero means context.Background() with no timeout
		handlerStatus       int
		handlerMessage      string
		succeedOnAttempt    int // returns success instead of handlerStatus after this many attempts; 0 means never succeed
		wantErrContains     string
		wantErrIs           error
		wantUserInfo        *UserInfo
		wantAttempts        int
	}{
		{
			name:                "retries once on a 401 then succeeds, when retryOnUnauthorized is true",
			retryOnUnauthorized: true,
			handlerStatus:       http.StatusUnauthorized,
			handlerMessage:      "bad credentials",
			succeedOnAttempt:    2,
			wantUserInfo:        &UserInfo{Login: "some-username", ID: "12345678"},
			wantAttempts:        2,
		},
		{
			name:                "exhausts retries and fails when every attempt returns a 401, when retryOnUnauthorized is true",
			retryOnUnauthorized: true,
			handlerStatus:       http.StatusUnauthorized,
			handlerMessage:      "bad credentials",
			wantErrContains:     "401 bad credentials",
			wantAttempts:        1 + defaultUnauthorizedMaxRetries,
		},
		{
			name:                "does not retry a 401 when retryOnUnauthorized is false",
			retryOnUnauthorized: false,
			handlerStatus:       http.StatusUnauthorized,
			handlerMessage:      "bad credentials",
			wantErrContains:     "401 bad credentials",
			wantAttempts:        1,
		},
		{
			name:                "does not retry a non-401 error even when retryOnUnauthorized is true",
			retryOnUnauthorized: true,
			handlerStatus:       http.StatusForbidden,
			handlerMessage:      "rate limited",
			wantErrContains:     "403 rate limited",
			wantAttempts:        1,
		},
		{
			name:                "returns promptly when the context is canceled during the retry wait",
			retryOnUnauthorized: true,
			retryDelay:          time.Hour, // long enough that a real wait would fail the test
			ctxTimeout:          50 * time.Millisecond,
			handlerStatus:       http.StatusUnauthorized,
			handlerMessage:      "bad credentials",
			wantErrIs:           context.DeadlineExceeded,
			wantAttempts:        1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attempts := new(int)

			httpClient := mock.NewMockedHTTPClient(
				mock.WithRequestMatchHandler(mock.GetUser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					*attempts++
					if *attempts == test.succeedOnAttempt {
						_, err := w.Write([]byte(`{"login":"some-username","id":12345678}`))
						require.NoError(t, err)
						return
					}
					mock.WriteError(w, test.handlerStatus, test.handlerMessage)
				})),
			)

			c, err := github.NewClient(github.WithHTTPClient(httpClient), github.WithAuthToken("some-token"))
			require.NoError(t, err)

			githubClient := &githubClient{
				client:                 c,
				unauthorizedRetryDelay: test.retryDelay,
				unauthorizedMaxRetries: defaultUnauthorizedMaxRetries,
			}

			ctx := context.Background()
			if test.ctxTimeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.ctxTimeout)
				defer cancel()
			}

			actual, err := githubClient.GetUserInfo(ctx, test.retryOnUnauthorized)
			require.Equal(t, test.wantAttempts, *attempts)
			switch {
			case test.wantErrContains != "":
				require.ErrorContains(t, err, test.wantErrContains)
			case test.wantErrIs != nil:
				require.ErrorIs(t, err, test.wantErrIs)
			default:
				require.NoError(t, err)
				require.Equal(t, test.wantUserInfo, actual)
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
						{Login: new("org1")},
						{Login: new("org2")},
						{Login: new("org3")},
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
						{Login: new("page1-org1")},
						{Login: new("page1-org2")},
						{Login: new("page1-org3")},
					},
					[]github.Organization{
						{Login: new("page2-org1")},
						{Login: new("page2-org2")},
						{Login: new("page2-org3")},
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
						{Login: new("page1-org1")},
						{Login: nil},
						{Login: new("page1-org3")},
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

			c, err := github.NewClient(github.WithHTTPClient(test.httpClient), github.WithAuthToken(test.token))
			require.NoError(t, err)
			githubClient := &githubClient{client: c}

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
							Name: new("orgAlpha-team1-name"),
							Slug: new("orgAlpha-team1-slug"),
							Organization: &github.Organization{
								Login: new("alpha"),
							},
						},
						{
							Name: new("orgAlpha-team2-name"),
							Slug: new("orgAlpha-team2-slug"),
							Organization: &github.Organization{
								Login: new("alpha"),
							},
						},
						{
							Name: new("orgAlpha-team3-name"),
							Slug: new("orgAlpha-team3-slug"),
							Organization: &github.Organization{
								Login: new("alpha"),
							},
						},
						{
							Name: new("orgBeta-team1-name"),
							Slug: new("orgBeta-team1-slug"),
							Organization: &github.Organization{
								Login: new("beta"),
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
							Name: new("team1-name"),
							Slug: new("team1-slug"),
							Organization: &github.Organization{
								Login: new("alPhA"),
							},
						},
						{
							Name: new("team2-name"),
							Slug: new("team2-slug"),
							Organization: &github.Organization{
								Login: new("bEtA"),
							},
						},
						{
							Name: new("team3-name"),
							Slug: new("team3-slug"),
							Organization: &github.Organization{
								Login: new("gAmmA"),
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
							Name: new("team1-name"),
							Slug: new("team1-slug"),
							Organization: &github.Organization{
								Login: new("alpha"),
							},
						},
						{
							Name: new("team2-name"),
							Slug: new("team2-slug"),
							Organization: &github.Organization{
								Login: new("beta"),
							},
						},
						{
							Name: new("team3-name"),
							Slug: new("team3-slug"),
							Parent: &github.Team{
								Name:         new("delta-team-name"),
								Slug:         new("delta-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: new("gamma"),
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
							Name: new("team-name-with-parent"),
							Slug: new("team-slug-with-parent"),
							Parent: &github.Team{
								Name:         new("parent-team-name"),
								Slug:         new("parent-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: new("org-with-nested-teams"),
							},
						},
						{
							Name: new("team-name-with-same-parent-again"),
							Slug: new("team-slug-with-same-parent-again"),
							Parent: &github.Team{
								Name:         new("parent-team-name"),
								Slug:         new("parent-team-slug"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: new("org-with-nested-teams"),
							},
						},
						{
							Name: new("parent-team-name"),
							Slug: new("parent-team-slug"),
							Organization: &github.Organization{
								Login: new("org-with-nested-teams"),
							},
						},
						{
							Name: new("team-name-with-parent-from-disallowed-org"),
							Slug: new("team-slug-with-parent-from-disallowed-org"),
							Parent: &github.Team{
								Name:         new("parent-team-name-from-disallowed-org"),
								Slug:         new("parent-team-slug-from-disallowed-org"),
								Organization: nil, // the real GitHub API does not return Org on "Parent" team.
							},
							Organization: &github.Organization{
								Login: new("disallowed-org"),
							},
						},
						{
							Name: new("team-name-without-parent"),
							Slug: new("team-slug-without-parent"),
							Organization: &github.Organization{
								Login: new("beta"),
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
							Name: new("page1-team-name"),
							Slug: new("page1-team-slug"),
							Organization: &github.Organization{
								Login: new("page1-org-name"),
							},
						},
					},
					[]github.Team{
						{
							Name: new("page2-team-name"),
							Slug: new("page2-team-slug"),
							Organization: &github.Organization{
								Login: new("page2-org-name"),
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
							Name: new("team-name"),
							Slug: new("team-slug"),
						},
					},
				),
			),
			token:   "fake-token",
			wantErr: `error fetching team membership for authenticated user: missing the "organization" attribute for a team`,
		},
		{
			name: "missing organization's login attribute returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name:         new("team-name"),
							Slug:         new("team-slug"),
							Organization: &github.Organization{},
						},
					},
				),
			),
			token:   "fake-token",
			wantErr: `error fetching team membership for authenticated user: missing the organization's "login" attribute for a team`,
		},
		{
			name: "missing the name attribute for a team returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Slug: new("team-slug"),
							Organization: &github.Organization{
								Login: new("some-org"),
							},
						},
					},
				),
			),
			token:   "fake-token",
			wantErr: `error fetching team membership for authenticated user: the "name" attribute is missing for a team`,
		},
		{
			name: "missing the slug attribute for a team returns an error",
			httpClient: mock.NewMockedHTTPClient(
				mock.WithRequestMatch(
					mock.GetUserTeams,
					[]github.Team{
						{
							Name: new("team-name"),
							Organization: &github.Organization{
								Login: new("some-org"),
							},
						},
					},
				),
			),
			token:   "fake-token",
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

			c, err := github.NewClient(github.WithHTTPClient(test.httpClient), github.WithAuthToken(test.token))
			require.NoError(t, err)
			githubClient := &githubClient{client: c}

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

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
