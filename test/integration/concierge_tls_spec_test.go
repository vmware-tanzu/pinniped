// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationConcierge_Parallel tests kubebuilder validation on the TLSSpec
// in Pinniped concierge CRDs for both WebhookAuthenticators and JWTAuthenticators.
func TestTLSSpecKubeBuilderValidationConcierge_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	testCases := []struct {
		name                           string
		customWebhookAuthenticatorYaml string
		customJWTAuthenticatorYaml     string
		resourceNamePrefix             string
		expectedError                  string
	}{
		{
			name: "should disallow certificate authority data source with missing name",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						key: bar
			`),
			resourceNamePrefix: "invalid-tls-spec-missing-name",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for name",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: ""
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: ""
						key: bar
			`),
			resourceNamePrefix: "invalid-tls-spec-empty-name",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing key",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
			`),
			resourceNamePrefix: "invalid-tls-spec-missing-key",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for key",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: ""
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: ""
			`),
			resourceNamePrefix: "invalid-tls-spec-empty-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						name: foo
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						name: foo
						key: bar
			`),
			resourceNamePrefix: "invalid-tls-spec-missing-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for kind",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: ""
						name: foo
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: ""
						name: foo
						key: bar
			`),
			resourceNamePrefix: "invalid-tls-spec-invalid-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should disallow certificate authority data source with invalid kind",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: sorcery
						name: foo
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: sorcery
						name: foo
						key: bar
			`),
			resourceNamePrefix: "invalid-tls-spec-invalid-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should create a custom resource passing all validations using a Secret source",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: bar
			`),
			resourceNamePrefix: "valid-webhook-auth-secret-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource passing all validations using a ConfigMap source",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
				tls:
					certificateAuthorityDataSource:
						kind: ConfigMap
						name: foo
						key: bar
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
				tls:
					certificateAuthorityDataSource:
						kind: ConfigMap
						name: foo
						key: bar
			`),
			resourceNamePrefix: "valid-webhook-auth-cm-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource without any tls spec",
			customWebhookAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
			`),
			customJWTAuthenticatorYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: JWTAuthenticator
			metadata:
				name: %s
			spec:
				issuer: %s
				audience: some-audience
			`),
			resourceNamePrefix: "no-tls-spec",
			expectedError:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("apply webhook authenticator", func(t *testing.T) {
				webhookResourceName := tc.resourceNamePrefix + "-" + testlib.RandHex(t, 7)
				webhookYamlBytes := []byte(fmt.Sprintf(tc.customWebhookAuthenticatorYaml, env.APIGroupSuffix, webhookResourceName, env.TestWebhook.Endpoint))

				performKubectlApply(t, webhookYamlBytes, tc.expectedError, "WebhookAuthenticator", webhookResourceName)
			})

			t.Run("apply jwt authenticator", func(t *testing.T) {
				issuerURL, err := url.Parse(env.SupervisorUpstreamOIDC.CallbackURL)
				require.NoError(t, err)
				require.True(t, strings.HasSuffix(issuerURL.Path, "/callback"))
				issuerURL.Path = strings.TrimSuffix(issuerURL.Path, "/callback")

				jwtAuthenticatorResourceName := tc.resourceNamePrefix + "-" + testlib.RandHex(t, 7)
				jwtAuthenticatorYamlBytes := []byte(fmt.Sprintf(tc.customJWTAuthenticatorYaml, env.APIGroupSuffix, jwtAuthenticatorResourceName, issuerURL.String()))

				performKubectlApply(t, jwtAuthenticatorYamlBytes, tc.expectedError, "JWTAuthenticator", jwtAuthenticatorResourceName)
			})
		})
	}
}

func performKubectlApply(
	t *testing.T,
	yamlBytes []byte,
	expectedError string,
	resourceType string,
	resourceName string,
) {
	t.Helper()

	yamlFilepath := filepath.Join(t.TempDir(), fmt.Sprintf("tls-spec-validation-%s.yaml", resourceName))

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

	if expectedError == "" {
		require.Empty(t, stdErr.String())
		require.Regexp(t, "^(webhookauthenticator|jwtauthenticator)"+regexp.QuoteMeta(fmt.Sprintf(".authentication.concierge.pinniped.dev/%s created\n", resourceName)), stdOut.String())
		require.NoError(t, err)
	} else {
		require.Equal(t, fmt.Sprintf(expectedError, resourceType, resourceName), strings.TrimSuffix(stdErr.String(), "\n"))
	}
}
