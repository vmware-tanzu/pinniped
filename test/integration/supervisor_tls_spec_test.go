// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationSupervisor_Parallel tests kubebuilder validation
// on the TLSSpec in Pinniped supervisor CRDs using OIDCIdentityProvider as an example.
func TestTLSSpecValidationSupervisor_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ca, err := certauthority.New("pinniped-test", 24*time.Hour)
	require.NoError(t, err)
	indentedCAPEM := indentForHeredoc(string(ca.Bundle()))

	oidcIDPTemplate := here.Doc(`
		apiVersion: idp.supervisor.%s/v1alpha1
		kind: OIDCIdentityProvider
		metadata:
			name: %s
			namespace: %s
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
			namespace: %s
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
			namespace: %s
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
			namespace: %s
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
		name string

		tlsYAML func(secretOrConfigmapName string) string

		secretOrConfigmapKind     string
		secretType                string
		secretOrConfigmapDataYAML string

		wantErrorSnippets            []string
		wantGitHubErrorSnippets      []string
		wantTLSValidConditionMessage string
	}{
		{
			name: "should disallow certificate authority data source with missing name",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							key: bar
				`)
			},
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`},
			wantGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"spec.githubAPI.tls.certificateAuthorityDataSource.name: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for name",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: ""
							key: bar
				`)
			},
			wantErrorSnippets:       []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`},
			wantGitHubErrorSnippets: []string{`The %s "%s" is invalid: spec.githubAPI.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.githubAPI.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`},
		},
		{
			name: "should disallow certificate authority data source with missing key",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: foo
				`)
			},
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`},
			wantGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"spec.githubAPI.tls.certificateAuthorityDataSource.key: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for key",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: foo
							key: ""
				`)
			},
			wantErrorSnippets:       []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`},
			wantGitHubErrorSnippets: []string{`The %s "%s" is invalid: spec.githubAPI.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.githubAPI.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`},
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							name: foo
							key: bar
				`)
			},
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`},
			wantGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				"spec.githubAPI.tls.certificateAuthorityDataSource.kind: Required value",
			},
		},
		{
			name: "should disallow certificate authority data source with empty value for kind",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: ""
							name: foo
							key: bar
				`)
			},
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`},
			wantGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				`spec.githubAPI.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
			},
		},
		{
			name: "should disallow certificate authority data source with invalid kind",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: sorcery
							name: foo
							key: bar
				`)
			},
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`},
			wantGitHubErrorSnippets: []string{
				`The %s "%s" is invalid:`,
				`spec.githubAPI.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
			},
		},
		{
			name:                  "should create a custom resource passing all validations using a Secret source of type Opaque",
			secretOrConfigmapKind: "Secret",
			secretType:            string(corev1.SecretTypeOpaque),
			secretOrConfigmapDataYAML: here.Docf(`
				bar: |
					%s
			`, indentedCAPEM),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets:            nil,
			wantGitHubErrorSnippets:      nil,
			wantTLSValidConditionMessage: "spec.tls is valid: using configured CA bundle",
		},
		{
			name:                  "should create a custom resource passing all validations using a ConfigMap source",
			secretOrConfigmapKind: "ConfigMap",
			secretOrConfigmapDataYAML: here.Docf(`
				bar: |
					%s
			`, indentedCAPEM),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets:            nil,
			wantTLSValidConditionMessage: `spec.tls is valid: using configured CA bundle`,
		},
		{
			name:                         "should create a custom resource without any tls spec",
			tlsYAML:                      func(secretOrConfigmapName string) string { return "" },
			wantErrorSnippets:            nil,
			wantGitHubErrorSnippets:      nil,
			wantTLSValidConditionMessage: "spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("apply OIDC IDP", func(t *testing.T) {
				resourceName := "test-oidc-idp-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.SupervisorNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				yamlBytes := []byte(fmt.Sprintf(oidcIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorNamespace, env.SupervisorUpstreamOIDC.Issuer,
					indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName))))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`oidcidentityprovider.idp.supervisor.%s`, env.APIGroupSuffix),
					tc.wantErrorSnippets,
					"OIDCIdentityProvider",
					resourceName,
				)

				if tc.wantErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.SupervisorNamespace,
						"OIDCIdentityProvider",
						tc.wantTLSValidConditionMessage,
					)
				}
			})

			t.Run("apply LDAP IDP", func(t *testing.T) {
				resourceName := "test-ldap-idp-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.SupervisorNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				yamlBytes := []byte(fmt.Sprintf(ldapIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorNamespace, env.SupervisorUpstreamLDAP.Host,
					indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName))))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`ldapidentityprovider.idp.supervisor.%s`, env.APIGroupSuffix),
					tc.wantErrorSnippets,
					"LDAPIdentityProvider",
					resourceName,
				)

				if tc.wantErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.SupervisorNamespace,
						"LDAPIdentityProvider",
						tc.wantTLSValidConditionMessage,
					)
				}
			})

			t.Run("apply ActiveDirectory IDP", func(t *testing.T) {
				resourceName := "test-ad-idp-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.SupervisorNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				yamlBytes := []byte(fmt.Sprintf(activeDirectoryIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorNamespace, env.SupervisorUpstreamLDAP.Host,
					indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName))))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`activedirectoryidentityprovider.idp.supervisor.%s`, env.APIGroupSuffix),
					tc.wantErrorSnippets,
					"ActiveDirectoryIdentityProvider",
					resourceName,
				)

				if tc.wantErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.SupervisorNamespace,
						"ActiveDirectoryIdentityProvider",
						tc.wantTLSValidConditionMessage,
					)
				}
			})

			t.Run("apply GitHub IDP", func(t *testing.T) {
				resourceName := "test-github-idp-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.SupervisorNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				// GitHub is nested deeper.
				indentedTLSYAMLForGitHub := indentForHeredoc(indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName)))

				yamlBytes := []byte(fmt.Sprintf(githubIDPTemplate,
					env.APIGroupSuffix, resourceName, env.SupervisorNamespace, indentedTLSYAMLForGitHub))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`githubidentityprovider.idp.supervisor.%s`, env.APIGroupSuffix),
					tc.wantGitHubErrorSnippets,
					"GitHubIdentityProvider",
					resourceName,
				)

				if tc.wantGitHubErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.SupervisorNamespace,
						"GitHubIdentityProvider",
						// The tls spec location is different for GitHubIdentityProvider, so adjust the expectation.
						strings.Replace(tc.wantTLSValidConditionMessage, "spec.tls is ", "spec.githubAPI.tls is ", 1),
					)
				}
			})
		})
	}
}
