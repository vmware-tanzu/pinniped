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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationConcierge_Parallel tests kubebuilder validation on the TLSSpec
// in Pinniped concierge CRDs using WebhookAuthenticator as an example.
func TestTLSSpecKubeBuilderValidationConcierge_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	localUserAuthenticatorEndpoint := env.TestWebhook.Endpoint

	testCases := []struct {
		name               string
		customResourceYaml string
		customResourceName string
		expectedError      string
	}{
		// TODO: should we repeat these tests using the JWTAuthenticator too?
		{
			name: "should disallow certificate authority data source with missing name",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-missing-name",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for name",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-empty-name",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing key",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-missing-key",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for key",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-empty-kind",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-missing-kind",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for kind",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-invalid-kind",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should disallow certificate authority data source with invalid kind",
			customResourceYaml: here.Doc(`
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
			customResourceName: "invalid-webhook-auth-invalid-kind",
			expectedError:      `The WebhookAuthenticator "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should create a custom resource passing all validations using a Secret source",
			customResourceYaml: here.Doc(`
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
			customResourceName: "valid-webhook-auth-secret-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource passing all validations using a ConfigMap source",
			customResourceYaml: here.Doc(`
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
			customResourceName: "valid-webhook-auth-cm-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource without any tls spec",
			customResourceYaml: here.Doc(`
			---
			apiVersion: authentication.concierge.%s/v1alpha1
			kind: WebhookAuthenticator
			metadata:
				name: %s
			spec:
				endpoint: %s
			`),
			customResourceName: "no-tls-spec",
			expectedError:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			yamlFilepath := filepath.Join(t.TempDir(), fmt.Sprintf("tls-spec-validation-%s.yaml", tc.customResourceName))

			resourceName := tc.customResourceName + "-" + testlib.RandHex(t, 7)
			yamlBytes := []byte(fmt.Sprintf(tc.customResourceYaml, env.APIGroupSuffix, resourceName, localUserAuthenticatorEndpoint))

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

			if tc.expectedError == "" {
				assert.Empty(t, stdErr.String())
				assert.Equal(t, fmt.Sprintf("webhookauthenticator.authentication.concierge.pinniped.dev/%s created\n", resourceName), stdOut.String())
				require.NoError(t, err)
			} else {
				require.Equal(t, fmt.Sprintf(tc.expectedError, resourceName), strings.TrimSuffix(stdErr.String(), "\n"))
			}
		})
	}
}
