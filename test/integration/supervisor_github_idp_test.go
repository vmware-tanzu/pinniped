// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"

	"go.pinniped.dev/test/testlib"
)

func TestGitHubIDPStaticValidationOnCreate_Parallel(t *testing.T) {
	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-github-idp-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(ns.Name)

	t.Parallel()

	tests := []struct {
		name         string
		inputSpec    idpv1alpha1.GitHubIdentityProviderSpec
		expectedSpec idpv1alpha1.GitHubIdentityProviderSpec
		expectedErr  string
	}{
		{
			name: "all fields set",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubApi: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("some-host.example.com"),
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: "pretend-ca-cert",
					},
				},
				AllowedOrganizations: []string{
					"org1",
					"that-other-org",
				},
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllowedOrgsOnly),
				Claims: idpv1alpha1.GitHubClaims{
					Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
					Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "any-name-goes-here",
				},
			},
			expectedSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubApi: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("some-host.example.com"),
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: "pretend-ca-cert",
					},
				},
				AllowedOrganizations: []string{
					"org1",
					"that-other-org",
				},
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllowedOrgsOnly),
				Claims: idpv1alpha1.GitHubClaims{
					Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
					Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "any-name-goes-here",
				},
			},
		},
		{
			name: "minimum fields set - inherit defaults",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllOrgsAllowed),
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubApi: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("github.com"),
				},
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllOrgsAllowed),
				Claims: idpv1alpha1.GitHubClaims{
					Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
					Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
		},
		{
			name: "cannot set OrganizationLoginPolicy=AllOrgsAllowed and set AllowedOrganizations",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowedOrganizations: []string{
					"some-org",
				},
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllOrgsAllowed),
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: "organizationLoginPolicy must be 'AllowedOrganizationsOnly' if allowedOrganizations are listed, or 'AllOrganizationsAllowed' if no allowedOrganizations are listed",
		},
		{
			name: "must have no more than 64 allowedOrganizations",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowedOrganizations: func() []string {
					var orgs []string
					for i := 0; i < 100; i++ {
						orgs = append(orgs, fmt.Sprintf("org-%d", i))
					}
					return orgs
				}(),
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllowedOrgsOnly),
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: "spec.allowedOrganizations: Too many: 100: must have at most 64 items",
		},
		{
			name: "cannot set OrganizationLoginPolicy=AllowedOrganizationsOnly and not set AllowedOrganizations",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllowedOrgsOnly),
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: "organizationLoginPolicy must be 'AllowedOrganizationsOnly' if allowedOrganizations are listed, or 'AllOrganizationsAllowed' if no allowedOrganizations are listed",
		},
		{
			name:        "spec.client.secretName in body should be at least 1 chars long",
			inputSpec:   idpv1alpha1.GitHubIdentityProviderSpec{},
			expectedErr: "spec.client.secretName in body should be at least 1 chars long",
		},
		{
			name: "cannot duplicate allowedOrganizations",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllowedOrgsOnly),
				AllowedOrganizations: []string{
					"org1",
					"org1",
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: `spec.allowedOrganizations[1]: Duplicate value: "org1"`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := &idpv1alpha1.GitHubIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "integration-test-",
				},
				Spec: tt.inputSpec,
			}

			outputGitHubIDP, err := gitHubIDPClient.Create(ctx, input, metav1.CreateOptions{})
			if tt.expectedErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.expectedSpec, outputGitHubIDP.Spec)
			} else {
				require.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestGitHubIDPInvalidHostStaticValidationOnCreate_Parallel(t *testing.T) {
	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-github-idp-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(ns.Name)

	t.Parallel()

	tests := []struct {
		name        string
		host        string
		expectedErr string
	}{
		{
			name:        "spec.gitHubAPI.host in body should be at least 1 chars long",
			host:        "",
			expectedErr: "spec.gitHubAPI.host in body should be at least 1 chars long",
		},
		{
			name:        "full URLs are not allowed for spec.gitHubAPI.host",
			host:        "https://example.com",
			expectedErr: "Do not specify a URL, only a domain name",
		},
		{
			name:        "ports are not allowed for spec.gitHubAPI.host",
			host:        "integration.test.local.example:443",
			expectedErr: "Do not specify a URL, only a domain name",
		},
		{
			name:        "schemes are not allowed for spec.gitHubAPI.host",
			host:        "http://example.com",
			expectedErr: "Do not specify a URL, only a domain name",
		},
		{
			name:        "paths are not allowed for spec.gitHubAPI.host",
			host:        "example.com/foo",
			expectedErr: "Do not specify a path, only a domain name",
		},
		{
			name:        "queries are not allowed for spec.gitHubAPI.host",
			host:        "example.com?a=b",
			expectedErr: "Do not specify a query, only a domain name",
		},
		{
			name:        "fragments are not allowed for spec.gitHubAPI.host",
			host:        "example.com#a",
			expectedErr: "Do not specify a fragment, only a domain name",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := &idpv1alpha1.GitHubIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "integration-test-",
				},
				Spec: idpv1alpha1.GitHubIdentityProviderSpec{
					GitHubApi: idpv1alpha1.GitHubAPIConfig{
						Host: &tt.host,
					},
					OrganizationLoginPolicy: ptr.To(idpv1alpha1.GitHubOrganizationLoginPolicyAllOrgsAllowed),
					Client: idpv1alpha1.GitHubClientSpec{
						SecretName: "name-of-a-secret",
					},
				},
			}

			_, err = gitHubIDPClient.Create(ctx, input, metav1.CreateOptions{})
			require.ErrorContains(t, err, tt.expectedErr)
		})
	}
}
