// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationConcierge_Parallel tests kubebuilder validation on the TLSSpec
// in Pinniped concierge CRDs for both WebhookAuthenticators and JWTAuthenticators.
func TestTLSSpecValidationConcierge_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ca, err := certauthority.New("pinniped-test", 24*time.Hour)
	require.NoError(t, err)
	indentedCAPEM := indentForHeredoc(string(ca.Bundle()))

	webhookAuthenticatorYamlTemplate := here.Doc(`
		apiVersion: authentication.concierge.%s/v1alpha1
		kind: WebhookAuthenticator
		metadata:
			name: %s
		spec:
			endpoint: %s
			%s
	`)

	jwtAuthenticatorYamlTemplate := here.Doc(`
		apiVersion: authentication.concierge.%s/v1alpha1
		kind: JWTAuthenticator
		metadata:
			name: %s
		spec:
			issuer: %s
			audience: some-audience
			%s
	`)

	testCases := []struct {
		name string

		tlsYAML func(secretOrConfigmapName string) string

		secretOrConfigmapKind     string
		secretType                string
		secretOrConfigmapDataYAML string

		wantErrorSnippets            []string
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
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`},
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
			wantErrorSnippets: []string{`The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`},
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
			wantTLSValidConditionMessage: `spec.tls is valid: using configured CA bundle`,
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
			wantTLSValidConditionMessage: "spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("apply webhook authenticator", func(t *testing.T) {
				resourceName := "test-webhook-authenticator-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.ConciergeNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				yamlBytes := []byte(fmt.Sprintf(webhookAuthenticatorYamlTemplate,
					env.APIGroupSuffix, resourceName, env.TestWebhook.Endpoint,
					indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName))))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`webhookauthenticator.authentication.concierge.%s`, env.APIGroupSuffix),
					tc.wantErrorSnippets,
					"WebhookAuthenticator",
					resourceName,
				)

				if tc.wantErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.ConciergeNamespace,
						"WebhookAuthenticator",
						tc.wantTLSValidConditionMessage,
					)
				}
			})

			t.Run("apply jwt authenticator", func(t *testing.T) {
				_, supervisorIssuer := env.InferSupervisorIssuerURL(t)

				resourceName := "test-jwt-authenticator-" + testlib.RandHex(t, 7)

				secretOrConfigmapResourceName := createSecretOrConfigMapFromData(t,
					resourceName,
					env.ConciergeNamespace,
					tc.secretOrConfigmapKind,
					tc.secretType,
					tc.secretOrConfigmapDataYAML,
				)

				yamlBytes := []byte(fmt.Sprintf(jwtAuthenticatorYamlTemplate,
					env.APIGroupSuffix, resourceName, supervisorIssuer,
					indentForHeredoc(tc.tlsYAML(secretOrConfigmapResourceName))))

				stdOut, stdErr, err := performKubectlApply(t, resourceName, yamlBytes)
				requireKubectlApplyResult(t, stdOut, stdErr, err,
					fmt.Sprintf(`jwtauthenticator.authentication.concierge.%s`, env.APIGroupSuffix),
					tc.wantErrorSnippets,
					"JWTAuthenticator",
					resourceName,
				)

				if tc.wantErrorSnippets == nil {
					requireTLSValidConditionMessageOnResource(t,
						resourceName,
						env.ConciergeNamespace,
						"JWTAuthenticator",
						tc.wantTLSValidConditionMessage,
					)
				}
			})
		})
	}
}

func indentForHeredoc(s string) string {
	// Further indent every line except for the first line by four spaces.
	// Use four spaces because that's what here.Doc uses.
	// Do not indent the first line because the template already indents it.
	return strings.ReplaceAll(s, "\n", "\n    ")
}

func requireTLSValidConditionMessageOnResource(t *testing.T, resourceName string, namespace string, resourceType string, wantMessage string) {
	t.Helper()

	require.NotEmpty(t, resourceName, "bad test setup: empty resourceName")
	require.NotEmpty(t, resourceType, "bad test setup: empty resourceType")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	conciergeAuthClient := testlib.NewConciergeClientset(t).AuthenticationV1alpha1()
	supervisorIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1()

	switch resourceType {
	case "JWTAuthenticator":
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := conciergeAuthClient.JWTAuthenticators().Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	case "WebhookAuthenticator":
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := conciergeAuthClient.WebhookAuthenticators().Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	case "OIDCIdentityProvider":
		require.NotEmpty(t, namespace, "bad test setup: empty namespace")
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := supervisorIDPClient.OIDCIdentityProviders(namespace).Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	case "LDAPIdentityProvider":
		require.NotEmpty(t, namespace, "bad test setup: empty namespace")
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := supervisorIDPClient.LDAPIdentityProviders(namespace).Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	case "ActiveDirectoryIdentityProvider":
		require.NotEmpty(t, namespace, "bad test setup: empty namespace")
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := supervisorIDPClient.ActiveDirectoryIdentityProviders(namespace).Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	case "GitHubIdentityProvider":
		require.NotEmpty(t, namespace, "bad test setup: empty namespace")
		testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
			got, err := supervisorIDPClient.GitHubIdentityProviders(namespace).Get(ctx, resourceName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireConditionHasMessage(requireEventually, got.Status.Conditions, "TLSConfigurationValid", wantMessage)
		}, 10*time.Second, 1*time.Second, "expected resource %s to have condition message %q", resourceName, wantMessage)
	default:
		require.Failf(t, "unexpected resource type", "type %q", resourceType)
	}
}

func requireConditionHasMessage(assertions *require.Assertions, actualConditions []metav1.Condition, conditionType string, wantMessage string) {
	assertions.NotEmpty(actualConditions, "wanted to have conditions but was empty")
	for _, c := range actualConditions {
		if c.Type == conditionType {
			assertions.Equal(wantMessage, c.Message)
			return
		}
	}
	assertions.Failf("did not find condition with expected type",
		"type %q, actual conditions: %#v", conditionType, actualConditions)
}

func createSecretOrConfigMapFromData(
	t *testing.T,
	resourceNameSuffix string,
	namespace string,
	kind string,
	secretType string,
	dataYAML string,
) string {
	t.Helper()

	if kind == "" {
		// Nothing to create.
		return ""
	}

	require.NotEmpty(t, resourceNameSuffix, "bad test setup: empty resourceNameSuffix")
	require.NotEmpty(t, namespace, "bad test setup: empty namespace")

	var resourceYAML string
	lowerKind := strings.ToLower(kind)
	resourceName := lowerKind + "-" + resourceNameSuffix

	// Further indent every line except for the first line by four spaces.
	// Use four spaces because that's what here.Doc uses.
	// Do not indent the first line because the template already indents it.
	indentedDataYAML := strings.ReplaceAll(dataYAML, "\n", "\n    ")

	switch lowerKind {
	case "secret":
		require.NotEmpty(t, secretType, "bad test setup: empty secret type")
		resourceYAML = here.Docf(`
			apiVersion: v1
			kind: Secret
			metadata:
				name: %s
				namespace: %s
			type: %s
			stringData:
				%s
		`, resourceName, namespace, secretType, indentedDataYAML)
	case "configmap":
		resourceYAML = here.Docf(`
			apiVersion: v1
			kind: ConfigMap
			metadata:
				name: %s
				namespace: %s
			data:
				%s
		`, resourceName, namespace, indentedDataYAML)
	default:
		require.Failf(t, "unexpected kind in test setup", "kind was %q", kind)
	}

	stdOut, stdErr, err := performKubectlApply(t, resourceName, []byte(resourceYAML))
	require.NoErrorf(t, err,
		"expected kubectl apply to succeed but got: %s\nstdout: %s\nstderr: %s\nyaml:\n%s",
		err, stdOut, stdErr, resourceYAML)

	return resourceName
}

func performKubectlApply(t *testing.T, resourceName string, yamlBytes []byte) (string, string, error) {
	t.Helper()

	yamlFilepath := filepath.Join(t.TempDir(), fmt.Sprintf("test-perform-kubectl-apply-%s.yaml", resourceName))

	require.NoError(t, os.WriteFile(yamlFilepath, yamlBytes, 0600))

	// Use --validate=false to disable old client-side validations to avoid getting different error messages in Kube 1.24 and older.
	// Note that this also disables validations of unknown and duplicate fields, but that's not what this test is about.
	//nolint:gosec // this is test code.
	cmd := exec.CommandContext(context.Background(), "kubectl", []string{"apply", "--validate=false", "-f", yamlFilepath}...)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	err := cmd.Run()

	t.Cleanup(func() {
		t.Helper()
		//nolint:gosec // this is test code.
		require.NoError(t, exec.Command("kubectl", []string{"delete", "--ignore-not-found", "-f", yamlFilepath}...).Run())
	})

	return stdOut.String(), stdErr.String(), err
}

func requireKubectlApplyResult(
	t *testing.T,
	kubectlStdOut string,
	kubectlStdErr string,
	kubectlErr error,
	wantSuccessPrefix string,
	wantErrorSnippets []string,
	wantResourceType string,
	wantResourceName string,
) {
	t.Helper()

	if len(wantErrorSnippets) > 0 {
		require.Error(t, kubectlErr)
		actualErrorString := strings.TrimSuffix(kubectlStdErr, "\n")
		for i, snippet := range wantErrorSnippets {
			if i == 0 {
				snippet = fmt.Sprintf(snippet, wantResourceType, wantResourceName)
			}
			require.Contains(t, actualErrorString, snippet)
		}
	} else {
		require.Empty(t, kubectlStdErr)
		require.Regexp(t, regexp.QuoteMeta(wantSuccessPrefix)+regexp.QuoteMeta(fmt.Sprintf("/%s created\n", wantResourceName)), kubectlStdOut)
		require.NoError(t, kubectlErr)
	}
}
