// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/testutil"

	"go.pinniped.dev/test/testlib"
)

func TestGitHubIDPStaticValidationOnCreate_Parallel(t *testing.T) {
	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()
	skipCELTests := !testutil.KubeServerMinorVersionAtLeastInclusive(t, adminClient.Discovery(), 26)

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

	tests := []struct {
		name              string
		inputSpec         idpv1alpha1.GitHubIdentityProviderSpec
		expectedSpec      idpv1alpha1.GitHubIdentityProviderSpec
		usesCELValidation bool
		expectedErr       string
	}{
		{
			name: "all fields set",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubAPI: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("some-host.example.com"),
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: func() string {
							return base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\ndata goes here"))
						}(),
					},
				},
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Allowed: []string{
							"org1",
							"that-other-org",
						},
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					},
				},
				Claims: idpv1alpha1.GitHubClaims{
					Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
					Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "any-name-goes-here",
				},
			},
			expectedSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubAPI: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("some-host.example.com"),
					TLS: &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmRhdGEgZ29lcyBoZXJl",
					},
				},
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Allowed: []string{
							"org1",
							"that-other-org",
						},
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					},
				},
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
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubAPI: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To("github.com"),
				},
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
					},
				},
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
			name: fmt.Sprintf(
				"cannot set AllowedOrganizationsPolicy=%s and set AllowedOrganizations",
				string(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)),
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Allowed: []string{
							"some-org",
						},
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			usesCELValidation: true,
			expectedErr:       "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
		},
		{
			name: fmt.Sprintf("spec.allowAuthentication.organizations.policy must be '%s' when spec.allowAuthentication.organizations.allowed is empty (nil)", string(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)),
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			usesCELValidation: true,
			expectedErr:       "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
		},
		{
			name: fmt.Sprintf("spec.allowAuthentication.organizations.policy must be '%s' when spec.allowAuthentication.organizations.allowed is empty", string(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)),
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Allowed: []string{},
						Policy:  ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			usesCELValidation: true,
			expectedErr:       "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
		},
		{
			name:        "spec.client.secretName in body should be at least 1 chars long",
			inputSpec:   idpv1alpha1.GitHubIdentityProviderSpec{},
			expectedErr: "spec.client.secretName in body should be at least 1 chars long",
		},
		{
			name: "spec.githubAPI.host in body should be at least 1 chars long",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				GitHubAPI: idpv1alpha1.GitHubAPIConfig{
					Host: ptr.To(""),
				},
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: "spec.githubAPI.host in body should be at least 1 chars long",
		},
		{
			name: "duplicates not permitted in spec.allowAuthentication.organizations.allowed",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{
				AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
					Organizations: idpv1alpha1.GitHubOrganizationsSpec{
						Allowed: []string{
							"org1",
							"org1",
						},
						Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					},
				},
				Client: idpv1alpha1.GitHubClientSpec{
					SecretName: "name-of-a-secret",
				},
			},
			expectedErr: `spec.allowAuthentication.organizations.allowed[1]: Duplicate value: "org1"`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.usesCELValidation && skipCELTests {
				t.Skip("CEL is not available for current K8s version")
			}

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

func TestGitHubIDPTooManyOrganizationsStaticValidationOnCreate_Parallel(t *testing.T) {
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

	input := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "integration-test-",
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Allowed: func() []string {
						var orgs []string
						for i := 0; i < 100; i++ {
							orgs = append(orgs, fmt.Sprintf("org-%d", i))
						}
						return orgs
					}(),
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
				},
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: "name-of-a-secret",
			},
		},
	}

	_, err = gitHubIDPClient.Create(ctx, input, metav1.CreateOptions{})

	expectedErr := "spec.allowAuthentication.organizations.allowed: Invalid value: 100: spec.allowAuthentication.organizations.allowed in body should have at most 64 items"
	if testutil.KubeServerMinorVersionAtLeastInclusive(t, adminClient.Discovery(), 24) {
		expectedErr = "spec.allowAuthentication.organizations.allowed: Too many: 100: must have at most 64 items"
	}

	require.ErrorContains(t, err, expectedErr)
}
