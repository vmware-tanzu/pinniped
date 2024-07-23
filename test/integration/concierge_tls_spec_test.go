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

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationConcierge_Parallel tests kubebuilder validation on the TLSSpec
// in Pinniped concierge CRDs for both WebhookAuthenticators and JWTAuthenticators.
func TestTLSSpecKubeBuilderValidationConcierge_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

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
		name          string
		tlsYAML       string
		expectedError string
	}{
		{
			name: "should disallow certificate authority data source with missing name",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						key: bar
			`),
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`,
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
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing key",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
			`),
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`,
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
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			tlsYAML: here.Doc(`
				tls:
					certificateAuthorityDataSource:
						name: foo
						key: bar
			`),
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`,
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
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
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
			expectedError: `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
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
			expectedError: "",
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
			expectedError: "",
		},
		{
			name:          "should create a custom resource without any tls spec",
			tlsYAML:       "",
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Further indent every line except for the first line by four spaces.
			// Use four spaces because that's what here.Doc uses.
			// Do not indent the first line because the template already indents it.
			indentedTLSYAML := strings.ReplaceAll(tc.tlsYAML, "\n", "\n    ")

			t.Run("apply webhook authenticator", func(t *testing.T) {
				webhookResourceName := "test-webhook-authenticator-" + testlib.RandHex(t, 7)
				webhookYamlBytes := []byte(fmt.Sprintf(webhookAuthenticatorYamlTemplate,
					env.APIGroupSuffix, webhookResourceName, env.TestWebhook.Endpoint, indentedTLSYAML))

				performKubectlApply(
					t,
					webhookYamlBytes,
					`webhookauthenticator.authentication.concierge.pinniped.dev`,
					tc.expectedError,
					"WebhookAuthenticator",
					webhookResourceName,
				)
			})

			t.Run("apply jwt authenticator", func(t *testing.T) {
				_, supervisorIssuer := env.SupervisorUpstreamOIDC.InferTheIssuerURL(t)

				jwtAuthenticatorResourceName := "test-jwt-authenticator-" + testlib.RandHex(t, 7)
				jwtAuthenticatorYamlBytes := []byte(fmt.Sprintf(jwtAuthenticatorYamlTemplate,
					env.APIGroupSuffix, jwtAuthenticatorResourceName, supervisorIssuer, indentedTLSYAML))

				performKubectlApply(
					t,
					jwtAuthenticatorYamlBytes,
					`jwtauthenticator.authentication.concierge.pinniped.dev`,
					tc.expectedError,
					"JWTAuthenticator",
					jwtAuthenticatorResourceName,
				)
			})
		})
	}
}

func performKubectlApply(
	t *testing.T,
	yamlBytes []byte,
	expectedSuccessPrefix string,
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
		require.Regexp(t, regexp.QuoteMeta(expectedSuccessPrefix)+regexp.QuoteMeta(fmt.Sprintf("/%s created\n", resourceName)), stdOut.String())
		require.NoError(t, err)
	} else {
		require.Equal(t, fmt.Sprintf(expectedError, resourceType, resourceName), strings.TrimSuffix(stdErr.String(), "\n"))
	}
}
