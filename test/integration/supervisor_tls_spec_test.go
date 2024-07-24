// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"strings"
	"testing"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationSupervisor_Parallel tests kubebuilder validation
// on the TLSSpec in Pinniped supervisor CRDs using OIDCIdentityProvider as an example.
func TestTLSSpecKubeBuilderValidationSupervisor_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	oidcIDPTemplate := here.Doc(`
		apiVersion: idp.supervisor.%s/v1alpha1
		kind: OIDCIdentityProvider
		metadata:
			name: %s
		spec:
			issuer: %s
			authorizationConfig:
				additionalScopes: [offline_access, email]
				allowPasswordGrant: true
			client:
				secretName: foo-bar-client-credentials
			%s
	`)

	ldapIDPTemplate := here.Doc(`
		apiVersion: idp.supervisor.%s/v1alpha1
		kind: LDAPIdentityProvider
		metadata:
			name: %s
		spec:
			host: %s
			bind:
				secretName: foo-bar-bind-credentials
			userSearch:
				base: foo
				attributes:
					username: bar
					uid: baz
			%s
	`)

	activeDirectoryIDPTemplate := here.Doc(`
		apiVersion: idp.supervisor.%s/v1alpha1
		kind: ActiveDirectoryIdentityProvider
		metadata:
			name: %s
		spec:
			host: %s
			bind:
				secretName: foo-bar-bind-credentials
			%s
	`)

	githubIDPTemplate := here.Doc(`
		apiVersion: idp.supervisor.%s/v1alpha1
		kind: GitHubIdentityProvider
		metadata:
			name: %s
		spec:
			allowAuthentication:
				organizations:
					policy: AllGitHubUsers
			client:
				secretName: does-not-matter
			githubAPI:
				%s
	`)

	testCases := []struct {
		name                        string
		tlsYAML                     string
		expectedErrorSnippets       []string
		expectedGitHubErrorSnippets []string
	}{
		{
			name: "should disallow certificate authority data source with missing name",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						key: bar
			`),
			expectedErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`},
			expectedGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"* spec.githubAPI.tls.certificateAuthorityDataSource.name: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for name",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: ""
						key: bar
			`),
			expectedErrorSnippets:       []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`},
			expectedGitHubErrorSnippets: []string{`The %s "%s" is invalid: spec.githubAPI.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.githubAPI.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`},
		},
		{
			name: "should disallow certificate authority data source with missing key",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
			`),
			expectedErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`},
			expectedGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"* spec.githubAPI.tls.certificateAuthorityDataSource.key: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for key",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: ""
			`),
			expectedErrorSnippets:       []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`},
			expectedGitHubErrorSnippets: []string{`The %s "%s" is invalid: spec.githubAPI.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.githubAPI.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`},
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						name: foo
						key: bar
			`),
			expectedErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`},
			expectedGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"* spec.githubAPI.tls.certificateAuthorityDataSource.kind: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for kind",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: ""
						name: foo
						key: bar
			`),
			expectedErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`},
			expectedGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				`spec.githubAPI.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
			},
		},
		{
			name: "should disallow certificate authority data source with invalid kind",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: sorcery
						name: foo
						key: bar
			`),
			expectedErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`},
			expectedGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				`spec.githubAPI.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
			},
		},
		{
			name: "should create a custom resource passing all validations using a Secret source",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: bar
			`),
			expectedErrorSnippets:       nil,
			expectedGitHubErrorSnippets: nil,
		},
		{
			name: "should create a custom resource passing all validations using a ConfigMap source",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: ConfigMap
						name: foo
						key: bar
			`),
			expectedErrorSnippets:       nil,
			expectedGitHubErrorSnippets: nil,
		},
		{
			name:                        "should create a custom resource without any tls spec",
			tlsYAML:                     "",
			expectedErrorSnippets:       nil,
			expectedGitHubErrorSnippets: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Further indent every line except for the first line by four spaces.
			// Use four spaces because that's what here.Doc uses.
			// Do not indent the first line because the template already indents it.
			indentedTLSYAML := strings.ReplaceAll(tc.tlsYAML, "\n", "\n    ")

			t.Run("apply OIDC IDP", func(t *testing.T) {
				resourceName := "test-oidc-idp-" + testlib.RandHex(t, 7)
				yamlBytes := []byte(fmt.Sprintf(oidcIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorUpstreamOIDC.Issuer, indentedTLSYAML))

				performKubectlApply(
					t,
					yamlBytes,
					`oidcidentityprovider.idp.supervisor.pinniped.dev`,
					tc.expectedErrorSnippets,
					"OIDCIdentityProvider",
					resourceName,
				)
			})

			t.Run("apply LDAP IDP", func(t *testing.T) {
				resourceName := "test-ldap-idp-" + testlib.RandHex(t, 7)
				yamlBytes := []byte(fmt.Sprintf(ldapIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorUpstreamLDAP.Host, indentedTLSYAML))

				performKubectlApply(
					t,
					yamlBytes,
					`ldapidentityprovider.idp.supervisor.pinniped.dev`,
					tc.expectedErrorSnippets,
					"LDAPIdentityProvider",
					resourceName,
				)
			})

			t.Run("apply ActiveDirectory IDP", func(t *testing.T) {
				resourceName := "test-ad-idp-" + testlib.RandHex(t, 7)
				yamlBytes := []byte(fmt.Sprintf(activeDirectoryIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorUpstreamLDAP.Host, indentedTLSYAML))

				performKubectlApply(
					t,
					yamlBytes,
					`activedirectoryidentityprovider.idp.supervisor.pinniped.dev`,
					tc.expectedErrorSnippets,
					"ActiveDirectoryIdentityProvider",
					resourceName,
				)
			})

			t.Run("apply GitHub IDP", func(t *testing.T) {
				// GitHub is nested deeper
				indentedTLSYAMLForGitHub := strings.ReplaceAll(indentedTLSYAML, "\n", "\n    ")

				resourceName := "test-github-idp-" + testlib.RandHex(t, 7)
				yamlBytes := []byte(fmt.Sprintf(githubIDPTemplate,
					env.APIGroupSuffix, resourceName, indentedTLSYAMLForGitHub))

				performKubectlApply(
					t,
					yamlBytes,
					`githubidentityprovider.idp.supervisor.pinniped.dev`,
					tc.expectedGitHubErrorSnippets,
					"GitHubIdentityProvider",
					resourceName,
				)
			})
		})
	}
}
