// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/base64"
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
		wantTLSValidConditionMessage func(namespace string, secretOrConfigmapName string) string
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
			name: "should get error condition when using both fields of the tls spec",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityData: "some CA data"
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: foo
							key: bar
				`)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return "spec.tls is invalid: both tls.certificateAuthorityDataSource and tls.certificateAuthorityData provided"
			},
		},
		{
			name: "should get error condition when certificateAuthorityData is not base64 data",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityData: "this is not base64 encoded"
				`)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return `spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 4`
			},
		},
		{
			name: "should get error condition when certificateAuthorityData does not contain PEM data",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityData: "%s"
				`, base64.StdEncoding.EncodeToString([]byte("this is not PEM data")))
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return `spec.tls.certificateAuthorityData is invalid: no base64-encoded PEM certificates found in 28 bytes of data (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`
			},
		},
		{
			name: "should get error condition when using a ConfigMap source and the ConfigMap does not exist",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: this-cm-does-not-exist
							key: bar
				`)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: failed to get configmap "%s/this-cm-does-not-exist": configmap "this-cm-does-not-exist" not found`,
					namespace)
			},
		},
		{
			name: "should get error condition when using a Secret source and the Secret does not exist",
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Doc(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: this-secret-does-not-exist
							key: bar
				`)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: failed to get secret "%s/this-secret-does-not-exist": secret "this-secret-does-not-exist" not found`,
					namespace)
			},
		},
		{
			name:                  "should get error condition when using a Secret source and the Secret is the wrong type",
			secretOrConfigmapKind: "Secret",
			secretType:            "wrong-type",
			secretOrConfigmapDataYAML: here.Doc(`
				bar: "does not matter for this test"
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: secret "%s/%s" of type "wrong-type" cannot be used as a certificate authority data source`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a Secret source and the key does not exist",
			secretOrConfigmapKind: "Secret",
			secretType:            string(corev1.SecretTypeOpaque),
			secretOrConfigmapDataYAML: here.Doc(`
				foo: "foo is the wrong key"
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" not found in secret "%s/%s"`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a ConfigMap source and the key does not exist",
			secretOrConfigmapKind: "ConfigMap",
			secretOrConfigmapDataYAML: here.Doc(`
				foo: "foo is the wrong key"
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" not found in configmap "%s/%s"`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a Secret source and the key has an empty value",
			secretOrConfigmapKind: "Secret",
			secretType:            string(corev1.SecretTypeOpaque),
			secretOrConfigmapDataYAML: here.Doc(`
				bar: ""
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" has empty value in secret "%s/%s"`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a ConfigMap source and the key has an empty value",
			secretOrConfigmapKind: "ConfigMap",
			secretOrConfigmapDataYAML: here.Doc(`
				bar: ""
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" has empty value in configmap "%s/%s"`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a Secret source and the Secret contains data which is not in PEM format",
			secretOrConfigmapKind: "Secret",
			secretType:            string(corev1.SecretTypeOpaque),
			secretOrConfigmapDataYAML: here.Doc(`
				bar: "this is not a PEM cert"
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: Secret
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" with 22 bytes of data in secret "%s/%s" is not a PEM-encoded certificate (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
					namespace, secretOrConfigmapName)
			},
		},
		{
			name:                  "should get error condition when using a ConfigMap source and the ConfigMap contains data which is not in PEM format",
			secretOrConfigmapKind: "ConfigMap",
			secretOrConfigmapDataYAML: here.Doc(`
				bar: "this is not a PEM cert"
			`),
			tlsYAML: func(secretOrConfigmapName string) string {
				return here.Docf(`
					tls:
						certificateAuthorityDataSource:
							kind: ConfigMap
							name: %s
							key: bar
				`, secretOrConfigmapName)
			},
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return fmt.Sprintf(
					`spec.tls.certificateAuthorityDataSource is invalid: key "bar" with 22 bytes of data in configmap "%s/%s" is not a PEM-encoded certificate (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`,
					namespace, secretOrConfigmapName)
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
			wantErrorSnippets:       nil,
			wantGitHubErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return "spec.tls is valid: using configured CA bundle"
			},
		},
		{
			name:                  "should create a custom resource passing all validations using a Secret source of type tls",
			secretOrConfigmapKind: "Secret",
			secretType:            string(corev1.SecretTypeTLS),
			secretOrConfigmapDataYAML: here.Docf(`
				tls.crt: foo
				tls.key: foo
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
			wantErrorSnippets:       nil,
			wantGitHubErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return "spec.tls is valid: using configured CA bundle"
			},
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
			wantErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return `spec.tls is valid: using configured CA bundle`
			},
		},
		{
			name:                    "should create a custom resource without any tls spec",
			tlsYAML:                 func(secretOrConfigmapName string) string { return "" },
			wantErrorSnippets:       nil,
			wantGitHubErrorSnippets: nil,
			wantTLSValidConditionMessage: func(namespace string, secretOrConfigmapName string) string {
				return "spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image"
			},
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
						tc.wantTLSValidConditionMessage(env.SupervisorNamespace, secretOrConfigmapResourceName),
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
						tc.wantTLSValidConditionMessage(env.SupervisorNamespace, secretOrConfigmapResourceName),
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
						tc.wantTLSValidConditionMessage(env.SupervisorNamespace, secretOrConfigmapResourceName),
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
						strings.Replace(
							tc.wantTLSValidConditionMessage(env.SupervisorNamespace, secretOrConfigmapResourceName),
							"spec.tls", "spec.githubAPI.tls", 1),
					)
				}
			})
		})
	}
}
