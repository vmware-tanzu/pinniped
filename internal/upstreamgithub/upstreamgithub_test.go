// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamgithub

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
)

func TestGitHubProvider(t *testing.T) {
	subject := New(ProviderConfig{
		Name:               "foo",
		ResourceUID:        "resource-uid-12345",
		Host:               "fake-host",
		UsernameAttribute:  "fake-username-attribute",
		GroupNameAttribute: "fake-group-name-attribute",
		OAuth2Config: &oauth2.Config{
			ClientID:     "fake-client-id",
			ClientSecret: "fake-client-secret",
		},
		AllowedOrganizations:    []string{"fake-org", "fake-org2"},
		OrganizationLoginPolicy: v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers,
		AuthorizationURL:        "https://fake-authorization-url",
		HttpClient: &http.Client{
			Timeout: 1234509,
		},
	})

	require.Equal(t, ProviderConfig{
		Name:               "foo",
		ResourceUID:        "resource-uid-12345",
		Host:               "fake-host",
		UsernameAttribute:  "fake-username-attribute",
		GroupNameAttribute: "fake-group-name-attribute",
		OAuth2Config: &oauth2.Config{
			ClientID:     "fake-client-id",
			ClientSecret: "fake-client-secret",
		},
		AllowedOrganizations:    []string{"fake-org", "fake-org2"},
		OrganizationLoginPolicy: v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers,
		AuthorizationURL:        "https://fake-authorization-url",
		HttpClient: &http.Client{
			Timeout: 1234509,
		},
	}, subject.GetConfig())

	require.Equal(t, "foo", subject.GetName())
	require.Equal(t, types.UID("resource-uid-12345"), subject.GetResourceUID())
	require.Equal(t, "fake-client-id", subject.GetClientID())
	require.Equal(t, &oauth2.Config{
		ClientID:     "fake-client-id",
		ClientSecret: "fake-client-secret",
	}, subject.GetOAuth2Config())
	require.Equal(t, "fake-host", subject.GetHost())
	require.Equal(t, v1alpha1.GitHubUsernameAttribute("fake-username-attribute"), subject.GetUsernameAttribute())
	require.Equal(t, v1alpha1.GitHubGroupNameAttribute("fake-group-name-attribute"), subject.GetGroupNameAttribute())
	require.Equal(t, []string{"fake-org", "fake-org2"}, subject.GetAllowedOrganizations())
	require.Equal(t, v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers, subject.GetOrganizationLoginPolicy())
	require.Equal(t, "https://fake-authorization-url", subject.GetAuthorizationURL())
	require.Equal(t, &http.Client{
		Timeout: 1234509,
	}, subject.GetHttpClient())
}
