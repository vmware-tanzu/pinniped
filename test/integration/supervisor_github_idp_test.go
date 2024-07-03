// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"

	"go.pinniped.dev/test/testlib"
)

const generateNamePrefix = "integration-test-github-idp-"

func TestGitHubIDPStaticValidationOnCreate_Parallel(t *testing.T) {
	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()
	skipCELTests := !testutil.KubeServerMinorVersionAtLeastInclusive(t, adminClient.Discovery(), 26)

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(ns.Name)

	tests := []struct {
		name              string
		usesCELValidation bool
		inputSpec         idpv1alpha1.GitHubIdentityProviderSpec
		wantSpec          idpv1alpha1.GitHubIdentityProviderSpec
		wantErr           string
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
			wantSpec: idpv1alpha1.GitHubIdentityProviderSpec{
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
			wantSpec: idpv1alpha1.GitHubIdentityProviderSpec{
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
			usesCELValidation: true,
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
			wantErr: "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
		},
		{
			name:              fmt.Sprintf("spec.allowAuthentication.organizations.policy must be '%s' when spec.allowAuthentication.organizations.allowed is empty (nil)", string(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)),
			usesCELValidation: true,
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
			wantErr: "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
		},
		{
			name:              fmt.Sprintf("spec.allowAuthentication.organizations.policy must be '%s' when spec.allowAuthentication.organizations.allowed is empty", string(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)),
			usesCELValidation: true,
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
			wantErr: "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
		},
		{
			name:      "spec.client.secretName in body should be at least 1 chars long",
			inputSpec: idpv1alpha1.GitHubIdentityProviderSpec{},
			wantErr:   "spec.client.secretName in body should be at least 1 chars long",
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
			wantErr: "spec.githubAPI.host in body should be at least 1 chars long",
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
			wantErr: `spec.allowAuthentication.organizations.allowed[1]: Duplicate value: "org1"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.usesCELValidation && skipCELTests {
				t.Skip("CEL is not available for current K8s version")
			}

			input := &idpv1alpha1.GitHubIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: generateNamePrefix,
				},
				Spec: tt.inputSpec,
			}

			outputGitHubIDP, err := gitHubIDPClient.Create(ctx, input, metav1.CreateOptions{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.wantSpec, outputGitHubIDP.Spec)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestGitHubIDPSetsDefaultsWithKubectl_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})
	t.Logf("Created namespace %s", ns.Name)

	idpName := generateNamePrefix + testlib.RandHex(t, 16)

	githubIDPYaml := []byte(here.Doc(fmt.Sprintf(`
	---
	apiVersion: idp.supervisor.%s/v1alpha1
	kind: GitHubIdentityProvider
	metadata:
	  name: %s
	  namespace: %s
	spec:
	  allowAuthentication:
	    organizations:
	      policy: AllGitHubUsers
	  client:
	    secretName: any-secret-name`, env.APIGroupSuffix, idpName, ns.Name)))

	githubIDPYamlFilepath := filepath.Join(t.TempDir(), "github-idp.yaml")

	require.NoError(t, os.WriteFile(githubIDPYamlFilepath, githubIDPYaml, 0600))

	stdOut, stdErr := runTestKubectlCommand(t, "create", "-f", githubIDPYamlFilepath)

	require.Equal(t, fmt.Sprintf("githubidentityprovider.idp.supervisor.%s/%s created\n", env.APIGroupSuffix, idpName), stdOut)
	require.Empty(t, stdErr)

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(ns.Name)

	idp, err := gitHubIDPClient.Get(ctx, idpName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, idpv1alpha1.GitHubIdentityProviderSpec{
		GitHubAPI: idpv1alpha1.GitHubAPIConfig{
			Host: ptr.To("github.com"),
		},
		Claims: idpv1alpha1.GitHubClaims{
			Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
			Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
		},
		AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
			Organizations: idpv1alpha1.GitHubOrganizationsSpec{
				Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
			},
		},
		Client: idpv1alpha1.GitHubClientSpec{
			SecretName: "any-secret-name",
		},
	}, idp.Spec)
}

func TestGitHubIDPPhaseAndConditions_Parallel(t *testing.T) {
	// These operations must be performed in the Supervisor's namespace so that the controller can find GitHubIdentityProvider
	supervisorNamespace := testlib.IntegrationEnv(t).SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	kubernetesClient := testlib.NewKubernetesClientset(t)
	secretsClient := kubernetesClient.CoreV1().Secrets(supervisorNamespace)
	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(supervisorNamespace)

	happySecretName := generateNamePrefix + testlib.RandHex(t, 16)
	invalidSecretName := generateNamePrefix + testlib.RandHex(t, 16)

	tests := []struct {
		name           string
		secrets        []*corev1.Secret // Secrets will be created first, and the first secret found will be listed as the configured GitHub Client secret
		idps           []*idpv1alpha1.GitHubIdentityProvider
		wantPhase      idpv1alpha1.GitHubIdentityProviderPhase
		wantConditions []*metav1.Condition
	}{
		{
			name: "Happy Path",
			secrets: []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: happySecretName,
					},
					Type: "secrets.pinniped.dev/github-client",
					Data: map[string][]byte{
						"clientID":     []byte("foo"),
						"clientSecret": []byte("bar"),
					},
				},
			},
			idps: []*idpv1alpha1.GitHubIdentityProvider{
				{
					Spec: idpv1alpha1.GitHubIdentityProviderSpec{
						GitHubAPI: idpv1alpha1.GitHubAPIConfig{
							Host: ptr.To("github.com"),
						},
						AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
							Organizations: idpv1alpha1.GitHubOrganizationsSpec{
								Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
							},
						},
					},
				},
			},
			wantPhase: idpv1alpha1.GitHubPhaseReady,
			wantConditions: []*metav1.Condition{
				{
					Type:    "ClaimsValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: "spec.claims are valid",
				},
				{
					Type:    "ClientCredentialsSecretValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: fmt.Sprintf("clientID and clientSecret have been read from spec.client.SecretName (%q)", happySecretName),
				},
				{
					Type:    "GitHubConnectionValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.githubAPI.host ("github.com:443") is reachable and TLS verification succeeds`,
				},
				{
					Type:    "HostValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.githubAPI.host ("github.com") is valid`,
				},
				{
					Type:    "OrganizationsPolicyValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: "spec.githubAPI.tls is valid: no TLS configuration provided",
				},
			},
		},
		{
			name: "Invalid Client Secret",
			secrets: []*corev1.Secret{
				{
					Type: "secrets.pinniped.dev/github-client",
					ObjectMeta: metav1.ObjectMeta{
						Name: invalidSecretName,
					},
				},
			},
			idps: []*idpv1alpha1.GitHubIdentityProvider{
				{
					Spec: idpv1alpha1.GitHubIdentityProviderSpec{
						GitHubAPI: idpv1alpha1.GitHubAPIConfig{
							Host: ptr.To("github.com"),
						},
						AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
							Organizations: idpv1alpha1.GitHubOrganizationsSpec{
								Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
							},
						},
						Client: idpv1alpha1.GitHubClientSpec{
							SecretName: invalidSecretName,
						},
					},
				},
			},
			wantPhase: idpv1alpha1.GitHubPhaseError,
			wantConditions: []*metav1.Condition{
				{
					Type:    "ClaimsValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: "spec.claims are valid",
				},
				{
					Type:   "ClientCredentialsSecretValid",
					Status: metav1.ConditionFalse,
					Reason: "SecretNotFound",
					Message: fmt.Sprintf(`missing key "clientID": secret from spec.client.SecretName (%q) must be found in namespace %q with type "secrets.pinniped.dev/github-client" and keys "clientID" and "clientSecret"`,
						invalidSecretName,
						supervisorNamespace),
				},
				{
					Type:    "GitHubConnectionValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.githubAPI.host ("github.com:443") is reachable and TLS verification succeeds`,
				},
				{
					Type:    "HostValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.githubAPI.host ("github.com") is valid`,
				},
				{
					Type:    "OrganizationsPolicyValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  metav1.ConditionTrue,
					Reason:  "Success",
					Message: `spec.githubAPI.tls is valid: no TLS configuration provided`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var secretName string
			for _, secret := range tt.secrets {
				secret.GenerateName = generateNamePrefix

				created, err := secretsClient.Create(ctx, secret, metav1.CreateOptions{})
				require.NoError(t, err)
				t.Cleanup(func() {
					err := secretsClient.Delete(ctx, created.Name, metav1.DeleteOptions{})
					require.NoError(t, err)
				})
				if secretName == "" {
					secretName = created.Name
				}
			}

			for _, idp := range tt.idps {
				idp.Name = ""
				idp.GenerateName = generateNamePrefix
				idp.Spec.Client.SecretName = secretName

				created, err := gitHubIDPClient.Create(ctx, idp, metav1.CreateOptions{})
				require.NoError(t, err)

				t.Cleanup(func() {
					err := gitHubIDPClient.Delete(ctx, created.Name, metav1.DeleteOptions{})
					require.NoError(t, err)
				})
				testlib.WaitForGitHubIDPPhase(ctx, t, gitHubIDPClient, created.Name, tt.wantPhase)
				testlib.WaitForGitHubIdentityProviderStatusConditions(ctx, t, gitHubIDPClient, created.Name, tt.wantConditions)
			}
		})
	}
}

func TestGitHubIDPInWrongNamespace_Parallel(t *testing.T) {
	// The GitHubIdentityProvider must be in the same namespace as the controller
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	kubernetesClient := testlib.NewKubernetesClientset(t)

	namespaceClient := kubernetesClient.CoreV1().Namespaces()
	otherNamespace, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, otherNamespace.Name, metav1.DeleteOptions{}))
	})

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(otherNamespace.Name)

	idp := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
			Namespace:    otherNamespace.Name,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To("github.com"),
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: "does-not-matter",
			},
		},
	}

	createdIDP, err := gitHubIDPClient.Create(ctx, idp, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		err := gitHubIDPClient.Delete(ctx, createdIDP.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	// We require that there's never an error
	// ... and that the status phase is never anything but Pending
	// ... and that there are no status conditions
	require.Never(t, func() bool {
		idp, err := gitHubIDPClient.Get(ctx, createdIDP.Name, metav1.GetOptions{})
		return err != nil && idp.Status.Phase != idpv1alpha1.GitHubPhasePending && len(idp.Status.Conditions) > 0
	}, 2*time.Minute, 10*time.Second)
}

func TestGitHubIDPSecretInOtherNamespace_Parallel(t *testing.T) {
	// The GitHubIdentityProvider must be in the same namespace as the controller
	supervisorNamespace := testlib.IntegrationEnv(t).SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	kubernetesClient := testlib.NewKubernetesClientset(t)
	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(supervisorNamespace)

	namespaceClient := kubernetesClient.CoreV1().Namespaces()
	otherNamespace, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, otherNamespace.Name, metav1.DeleteOptions{}))
	})

	secretsClient := kubernetesClient.CoreV1().Secrets(otherNamespace.Name)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
			Namespace:    otherNamespace.Name,
		},
		Type: "secrets.pinniped.dev/github-client",
		Data: map[string][]byte{
			"clientID":     []byte("foo"),
			"clientSecret": []byte("bar"),
		},
	}

	// This secret will be cleaned up when its namespace is deleted
	createdSecret, err := secretsClient.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	idp := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
			Namespace:    supervisorNamespace,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To("github.com"),
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: createdSecret.Name,
			},
		},
	}

	created, err := gitHubIDPClient.Create(ctx, idp, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		err := gitHubIDPClient.Delete(ctx, created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	testlib.WaitForGitHubIDPPhase(ctx, t, gitHubIDPClient, created.Name, idpv1alpha1.GitHubPhaseError)

	testlib.WaitForGitHubIdentityProviderStatusConditions(ctx, t, gitHubIDPClient, created.Name, []*metav1.Condition{
		{
			Type:    "ClaimsValid",
			Status:  metav1.ConditionTrue,
			Reason:  "Success",
			Message: "spec.claims are valid",
		},
		{
			Type:   "ClientCredentialsSecretValid",
			Status: metav1.ConditionFalse,
			Reason: "SecretNotFound",
			Message: fmt.Sprintf(`secret %q not found: secret from spec.client.SecretName (%q) must be found in namespace %q with type "secrets.pinniped.dev/github-client" and keys "clientID" and "clientSecret"`,
				idp.Spec.Client.SecretName,
				idp.Spec.Client.SecretName,
				supervisorNamespace),
		},
		{
			Type:    "GitHubConnectionValid",
			Status:  metav1.ConditionTrue,
			Reason:  "Success",
			Message: `spec.githubAPI.host ("github.com:443") is reachable and TLS verification succeeds`,
		},
		{
			Type:    "HostValid",
			Status:  metav1.ConditionTrue,
			Reason:  "Success",
			Message: `spec.githubAPI.host ("github.com") is valid`,
		},
		{
			Type:    "OrganizationsPolicyValid",
			Status:  metav1.ConditionTrue,
			Reason:  "Success",
			Message: `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
		},
		{
			Type:    "TLSConfigurationValid",
			Status:  metav1.ConditionTrue,
			Reason:  "Success",
			Message: "spec.githubAPI.tls is valid: no TLS configuration provided",
		},
	})
}

func TestGitHubIDPTooManyOrganizationsStaticValidationOnCreate_Parallel(t *testing.T) {
	adminClient := testlib.NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})

	gitHubIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().GitHubIdentityProviders(ns.Name)

	input := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateNamePrefix,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Allowed: func() []string {
						orgs := make([]string, 100)
						for i := range 100 {
							orgs[i] = fmt.Sprintf("org-%d", i)
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

	wantErr := "spec.allowAuthentication.organizations.allowed: Invalid value: 100: spec.allowAuthentication.organizations.allowed in body should have at most 64 items"
	if testutil.KubeServerMinorVersionAtLeastInclusive(t, adminClient.Discovery(), 24) {
		wantErr = "spec.allowAuthentication.organizations.allowed: Too many: 100: must have at most 64 items"
	}

	require.ErrorContains(t, err, wantErr)
}
