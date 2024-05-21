// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamgithub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/util/cert"

	supervisoridpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/githubclient"
	"go.pinniped.dev/internal/mocks/mockgithubclient"
	"go.pinniped.dev/internal/setutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestGitHubProvider(t *testing.T) {
	subject := New(ProviderConfig{
		Name:               "foo",
		ResourceUID:        "resource-uid-12345",
		APIBaseURL:         "https://fake-base-url",
		UsernameAttribute:  "fake-username-attribute",
		GroupNameAttribute: "fake-group-name-attribute",
		OAuth2Config: &oauth2.Config{
			ClientID:     "fake-client-id",
			ClientSecret: "fake-client-secret",
			Scopes:       []string{"scope1", "scope2"},
			Endpoint: oauth2.Endpoint{
				AuthURL:       "https://fake-authorization-url",
				DeviceAuthURL: "",
				TokenURL:      "https://fake-token-url",
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
		AllowedOrganizations: setutil.NewCaseInsensitiveSet("fake-org", "fake-org2"),
		HttpClient: &http.Client{
			Timeout: 1234509,
		},
	})

	require.Equal(t, ProviderConfig{
		Name:               "foo",
		ResourceUID:        "resource-uid-12345",
		APIBaseURL:         "https://fake-base-url",
		UsernameAttribute:  "fake-username-attribute",
		GroupNameAttribute: "fake-group-name-attribute",
		OAuth2Config: &oauth2.Config{
			ClientID:     "fake-client-id",
			ClientSecret: "fake-client-secret",
			Scopes:       []string{"scope1", "scope2"},
			Endpoint: oauth2.Endpoint{
				AuthURL:       "https://fake-authorization-url",
				DeviceAuthURL: "",
				TokenURL:      "https://fake-token-url",
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
		AllowedOrganizations: setutil.NewCaseInsensitiveSet("fake-org", "fake-org2"),
		HttpClient: &http.Client{
			Timeout: 1234509,
		},
	}, subject.GetConfig())

	require.Equal(t, "foo", subject.GetName())
	require.Equal(t, types.UID("resource-uid-12345"), subject.GetResourceUID())
	require.Equal(t, "fake-client-id", subject.GetClientID())
	require.Equal(t, "fake-client-id", subject.GetClientID())
	require.Equal(t, supervisoridpv1alpha1.GitHubUsernameAttribute("fake-username-attribute"), subject.GetUsernameAttribute())
	require.Equal(t, supervisoridpv1alpha1.GitHubGroupNameAttribute("fake-group-name-attribute"), subject.GetGroupNameAttribute())
	require.Equal(t, setutil.NewCaseInsensitiveSet("fake-org", "fake-org2"), subject.GetAllowedOrganizations())
	require.Equal(t, "https://fake-authorization-url", subject.GetAuthorizationURL())
	require.Equal(t, &http.Client{
		Timeout: 1234509,
	}, subject.GetConfig().HttpClient)
}

func TestExchangeAuthcode(t *testing.T) {
	const fakeGitHubAccessToken = "gho_16C7e42F292c6912E7710c838347Ae178B4a" //nolint:gosec // this is not a credential

	tests := []struct {
		name              string
		tokenEndpointPath string
		wantErr           string
	}{
		{
			name:              "happy path",
			tokenEndpointPath: "/token",
		},
		{
			name:              "when the GitHub token endpoint returns an error",
			tokenEndpointPath: "/token-error",
			wantErr:           "error exchanging authorization code using GitHub API: oauth2: cannot fetch token: 401 Unauthorized\nResponse: some github error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testServer, testServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// See documentation at https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
				// GitHub docs say to use a POST.
				require.Equal(t, http.MethodPost, r.Method)

				// The OAuth client library happens to choose to send these headers. Asserting here for our own understanding.
				require.Len(t, r.Header, 4)
				require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				require.Equal(t, "gzip", r.Header.Get("Accept-Encoding"))
				require.NotEmpty(t, r.Header.Get("User-Agent"))
				require.NotEmpty(t, r.Header.Get("Content-Length"))

				// Get the params.
				err := r.ParseForm()
				require.NoError(t, err)
				params := r.PostForm
				require.Len(t, params, 5)
				// These four params are documented by GitHub.
				require.Equal(t, "fake-client-id", params.Get("client_id"))
				require.Equal(t, "fake-client-secret", params.Get("client_secret"))
				require.Equal(t, "https://fake-redirect-url", params.Get("redirect_uri"))
				require.Equal(t, "fake-authcode", params.Get("code"))
				// This param is not documented by GitHub, but is standard OAuth2. GitHub should respect or ignore it.
				require.Equal(t, "authorization_code", params.Get("grant_type"))

				// The GitHub docs say that it will return a URL encoded form by default, so I assume it would set this header.
				w.Header().Set("content-type", "application/x-www-form-urlencoded")

				switch r.URL.Path {
				case "/token":
					// Example response from GitHub docs.
					responseBody := "access_token=" + fakeGitHubAccessToken + "&scope=repo%2Cgist&token_type=bearer"
					w.WriteHeader(http.StatusOK)
					_, err = w.Write([]byte(responseBody))
					require.NoError(t, err)
				case "/token-error":
					responseBody := "some github error"
					w.WriteHeader(http.StatusUnauthorized)
					_, err = w.Write([]byte(responseBody))
					require.NoError(t, err)
				default:
					t.Fatalf("tried to call provider at unexpected endpoint: %s", r.URL.Path)
				}
			}), nil)
			testServerPool, err := cert.NewPoolFromBytes(testServerCA)
			require.NoError(t, err)

			subject := New(ProviderConfig{
				OAuth2Config: &oauth2.Config{
					ClientID:     "fake-client-id",
					ClientSecret: "fake-client-secret",
					Scopes:       []string{"scope1", "scope2"},
					Endpoint: oauth2.Endpoint{
						AuthURL:   "https://fake-auth-url",
						TokenURL:  testServer.URL + test.tokenEndpointPath,
						AuthStyle: oauth2.AuthStyleInParams,
					},
				},
				HttpClient: &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{TLSClientConfig: &tls.Config{
						MinVersion: tls.VersionTLS12,
						RootCAs:    testServerPool,
					}},
				},
			})

			accessToken, err := subject.ExchangeAuthcode(context.Background(), "fake-authcode", "https://fake-redirect-url")
			if test.wantErr != "" {
				require.EqualError(t, err, test.wantErr)
				require.Empty(t, accessToken)
			} else {
				require.NoError(t, err)
				require.Equal(t, fakeGitHubAccessToken, accessToken)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	const idpDisplayName = "idp display name 😀"
	const encodedIDPDisplayName = "idp+display+name+%F0%9F%98%80"

	someContext := context.Background()

	someHttpClient := &http.Client{
		Timeout: 1234509,
	}

	tests := []struct {
		name                   string
		providerConfig         ProviderConfig
		buildGitHubClientError error
		buildMockResponses     func(hubInterface *mockgithubclient.MockGitHubInterface)
		wantUser               *upstreamprovider.GitHubUser
		wantErr                string
	}{
		{
			name: "happy path with username=login:id",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: supervisoridpv1alpha1.GitHubUsernameLoginAndID,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, gomock.Any()).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "happy path with username=login",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: supervisoridpv1alpha1.GitHubUsernameLogin,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, nil).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login",
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "happy path with username=id",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: supervisoridpv1alpha1.GitHubUsernameID,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, nil).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-id",
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "happy path with user in allowed organizations",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: setutil.NewCaseInsensitiveSet("ALLOWED-ORG1", "ALLOWED-ORG2"),
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return([]string{"allowed-org2"}, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, setutil.NewCaseInsensitiveSet("ALLOWED-ORG1", "ALLOWED-ORG2")).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "returns error when the user does not belong to the allowed organizations",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameID,
				AllowedOrganizations: setutil.NewCaseInsensitiveSet("allowed-org"),
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return([]string{"disallowed-org"}, nil)
			},
			wantErr: "user is not allowed to log in due to organization membership policy",
		},
		{
			name: "happy path with groups=name",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: setutil.NewCaseInsensitiveSet("allowed-org1", "allowed-org2"),
				GroupNameAttribute:   supervisoridpv1alpha1.GitHubUseTeamNameForGroupName,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return([]string{"allowed-org2"}, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, setutil.NewCaseInsensitiveSet("allowed-org1", "allowed-org2")).Return([]githubclient.TeamInfo{
					{
						Name: "org1-team1-name",
						Slug: "org1-team1-slug",
						Org:  "org1-name",
					},
					{
						Name: "org1-team2-name",
						Slug: "org1-team2-slug",
						Org:  "org1-name",
					},
					{
						Name: "org2-team1-name",
						Slug: "org2-team1-slug",
						Org:  "org2-name",
					},
				}, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				Groups:            []string{"org1-name/org1-team1-name", "org1-name/org1-team2-name", "org2-name/org2-team1-name"},
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "happy path with groups=slug",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: setutil.NewCaseInsensitiveSet("allowed-org1", "allowed-org2"),
				GroupNameAttribute:   supervisoridpv1alpha1.GitHubUseTeamSlugForGroupName,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return([]string{"allowed-org2"}, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, setutil.NewCaseInsensitiveSet("allowed-org1", "allowed-org2")).Return([]githubclient.TeamInfo{
					{
						Name: "org1-team1-name",
						Slug: "org1-team1-slug",
						Org:  "org1-name",
					},
					{
						Name: "org1-team2-name",
						Slug: "org1-team2-slug",
						Org:  "org1-name",
					},
					{
						Name: "org2-team1-name",
						Slug: "org2-team1-slug",
						Org:  "org2-name",
					},
				}, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				Groups:            []string{"org1-name/org1-team1-slug", "org1-name/org1-team2-slug", "org2-name/org2-team1-slug"},
				DownstreamSubject: fmt.Sprintf("https://some-url?idpName=%s&login=some-github-login&id=some-github-id", encodedIDPDisplayName),
			},
		},
		{
			name: "returns errors from buildGitHubClient()",
			providerConfig: ProviderConfig{
				APIBaseURL: "https://some-url",
				HttpClient: someHttpClient,
			},
			buildGitHubClientError: errors.New("error from building a github client"),
			wantErr:                "error from building a github client",
		},
		{
			name: "returns errors from githubClient.GetUserInfo()",
			providerConfig: ProviderConfig{
				APIBaseURL: "https://some-url",
				HttpClient: someHttpClient,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(nil, errors.New("error from githubClient.GetUserInfo"))
			},
			wantErr: "error from githubClient.GetUserInfo",
		},
		{
			name: "returns errors from githubClient.GetOrgMembership()",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: supervisoridpv1alpha1.GitHubUsernameLoginAndID,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, errors.New("error from githubClient.GetOrgMembership"))
			},
			wantErr: "error from githubClient.GetOrgMembership",
		},
		{
			name: "returns errors from githubClient.GetTeamMembership()",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: supervisoridpv1alpha1.GitHubUsernameLoginAndID,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, gomock.Any()).Return(nil, errors.New("error from githubClient.GetTeamMembership"))
			},
			wantErr: "error from githubClient.GetTeamMembership",
		},
		{
			name: "bad configuration: UsernameAttribute",
			providerConfig: ProviderConfig{
				APIBaseURL:        "https://some-url",
				HttpClient:        someHttpClient,
				UsernameAttribute: "this-is-not-legal-value-from-the-enum",
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
			},
			wantErr: "bad configuration: unknown GitHub username attribute: this-is-not-legal-value-from-the-enum",
		},
		{
			name: "bad configuration: GroupNameAttribute",
			providerConfig: ProviderConfig{
				APIBaseURL:         "https://some-url",
				HttpClient:         someHttpClient,
				UsernameAttribute:  supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				GroupNameAttribute: "this-is-not-legal-value-from-the-enum",
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, nil).Return([]githubclient.TeamInfo{
					{
						Name: "org1-team1-name",
						Slug: "org1-team1-slug",
						Org:  "org1-name",
					},
				}, nil)
			},
			wantErr: "bad configuration: unknown GitHub group name attribute: this-is-not-legal-value-from-the-enum",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			accessToken := "some-opaque-github-access-token" + rand.String(8)
			mockGitHubInterface := mockgithubclient.NewMockGitHubInterface(ctrl)
			if test.buildMockResponses != nil {
				test.buildMockResponses(mockGitHubInterface)
			}

			p := New(test.providerConfig)
			p.buildGitHubClient = func(httpClient *http.Client, apiBaseURL, token string) (githubclient.GitHubInterface, error) {
				require.Equal(t, test.providerConfig.HttpClient, httpClient)
				require.Equal(t, test.providerConfig.APIBaseURL, apiBaseURL)
				require.Equal(t, accessToken, token)

				return mockGitHubInterface, test.buildGitHubClientError
			}

			actualUser, actualErr := p.GetUser(context.Background(), accessToken, idpDisplayName)
			if test.wantErr != "" {
				require.EqualError(t, actualErr, test.wantErr)
				require.Nil(t, actualUser)
				return
			}
			require.NoError(t, actualErr)
			require.Equal(t, test.wantUser, actualUser)
		})
	}
}
