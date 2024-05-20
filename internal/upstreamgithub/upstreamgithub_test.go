// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamgithub

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"

	supervisoridpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/githubclient"
	"go.pinniped.dev/internal/mocks/mockgithubclient"
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
		AllowedOrganizations: []string{"fake-org", "fake-org2"},
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
		AllowedOrganizations: []string{"fake-org", "fake-org2"},
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
	require.Equal(t, []string{"fake-org", "fake-org2"}, subject.GetAllowedOrganizations())
	require.Equal(t, "https://fake-authorization-url", subject.GetAuthorizationURL())
	require.Equal(t, &http.Client{
		Timeout: 1234509,
	}, subject.GetConfig().HttpClient)
}

func TestGetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

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
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]()).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
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
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]()).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login",
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
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
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]()).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-id",
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
			},
		},
		{
			name: "happy path with user in allowed organizations",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: []string{"allowed-org1", "allowed-org2"},
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(sets.New[string]("allowed-org2"), nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]("allowed-org1", "allowed-org2")).Return(nil, nil)
			},
			wantUser: &upstreamprovider.GitHubUser{
				Username:          "some-github-login:some-github-id",
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
			},
		},
		{
			name: "returns error when the user does not belong to the allowed organizations",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameID,
				AllowedOrganizations: []string{"allowed-org"},
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(sets.New[string]("disallowed-org"), nil)
			},
			wantErr: "user is not allowed to log in due to organization membership policy",
		},
		{
			name: "happy path with groups=name",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: []string{"allowed-org1", "allowed-org2"},
				GroupNameAttribute:   supervisoridpv1alpha1.GitHubUseTeamNameForGroupName,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(sets.New[string]("allowed-org2"), nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]("allowed-org1", "allowed-org2")).Return([]*githubclient.TeamInfo{
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
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
			},
		},
		{
			name: "happy path with groups=slug",
			providerConfig: ProviderConfig{
				APIBaseURL:           "https://some-url",
				HttpClient:           someHttpClient,
				UsernameAttribute:    supervisoridpv1alpha1.GitHubUsernameLoginAndID,
				AllowedOrganizations: []string{"allowed-org1", "allowed-org2"},
				GroupNameAttribute:   supervisoridpv1alpha1.GitHubUseTeamSlugForGroupName,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{
					Login: "some-github-login",
					ID:    "some-github-id",
				}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(sets.New[string]("allowed-org2"), nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, sets.New[string]("allowed-org1", "allowed-org2")).Return([]*githubclient.TeamInfo{
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
				DownstreamSubject: "https://some-url?idpName=TODO_IDP_DISPLAY_NAME&login=some-github-login&id=some-github-id",
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
				APIBaseURL: "https://some-url",
				HttpClient: someHttpClient,
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
				APIBaseURL: "https://some-url",
				HttpClient: someHttpClient,
			},
			buildMockResponses: func(mockGitHubInterface *mockgithubclient.MockGitHubInterface) {
				mockGitHubInterface.EXPECT().GetUserInfo(someContext).Return(&githubclient.UserInfo{}, nil)
				mockGitHubInterface.EXPECT().GetOrgMembership(someContext).Return(nil, nil)
				mockGitHubInterface.EXPECT().GetTeamMembership(someContext, gomock.Any()).Return(nil, errors.New("error from githubClient.GetTeamMembership"))
			},
			wantErr: "error from githubClient.GetTeamMembership",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

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

			actualUser, actualErr := p.GetUser(context.Background(), accessToken)
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
