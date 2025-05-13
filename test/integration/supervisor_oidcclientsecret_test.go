// Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	clientsecretv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
)

func TestKubectlOIDCClientSecretRequest_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	tests := []struct {
		name                       string
		oicClientSecretRequestYAML func(string) string
		cmdInvocation              func(string) []string
		assertOnStdOut             func(t *testing.T, oidcClientName string, stdOutString string)
		assertOnStdErr             func(t *testing.T, oidcClientName, tempFileName, stdErrString string)
		wantErr                    string
	}{
		{
			name: "kubectl create oidcclientsecretrequest file will return a simple success status message",
			oicClientSecretRequestYAML: func(name string) string {
				return here.Docf(`
					apiVersion: clientsecret.supervisor.%s/v1alpha1
					kind: OIDCClientSecretRequest
					metadata:
					  name: %s
					  namespace: %s
					spec:
					  generateNewSecret: true
					  revokeOldSecrets: false
				`, env.APIGroupSuffix, name, env.SupervisorNamespace)
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"create", "-f", filePath}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				require.Equal(t, fmt.Sprintf("oidcclientsecretrequest.clientsecret.supervisor.%s/%s created\n", env.APIGroupSuffix, oidcClientName), stdOutString)
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				requireCleanKubectlStderr(t, stdErrString)
			},
		},
		{
			name: "kubectl apply an oidcclientsecretrequest file will return a simple success status message",
			oicClientSecretRequestYAML: func(name string) string {
				return here.Docf(`
					apiVersion: clientsecret.supervisor.%s/v1alpha1
					kind: OIDCClientSecretRequest
					metadata:
					  name: %s
					  namespace: %s
					spec:
					  generateNewSecret: true
					  revokeOldSecrets: false
				`, env.APIGroupSuffix, name, env.SupervisorNamespace)
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"apply", "-f", filePath}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				require.Equal(t, fmt.Sprintf("oidcclientsecretrequest.clientsecret.supervisor.%s/%s created\n", env.APIGroupSuffix, oidcClientName), stdOutString)
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				requireCleanKubectlStderr(t, stdErrString)
			},
		},
		{
			name: "kubectl create an oidcclientsecretrequest -o yaml will return a yaml doc with the correct structure",
			oicClientSecretRequestYAML: func(name string) string {
				return here.Docf(`
					apiVersion: clientsecret.supervisor.%s/v1alpha1
					kind: OIDCClientSecretRequest
					metadata:
					  name: %s
					  namespace: %s
					spec:
					  generateNewSecret: true
					  revokeOldSecrets: false
				`, env.APIGroupSuffix, name, env.SupervisorNamespace)
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"create", "-f", filePath, "-o", "yaml"}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				var yamlObj map[string]any
				err := yaml.Unmarshal([]byte(stdOutString), &yamlObj)
				require.NoError(t, err)

				require.Lenf(t, yamlObj, 5, "yaml object should have 5 top level keys (apiVersion, kind, metadata, spec, status): %v", yamlObj)
				require.Equal(t, yamlObj["apiVersion"], fmt.Sprintf("clientsecret.supervisor.%s/v1alpha1", env.APIGroupSuffix))
				require.Equal(t, yamlObj["kind"], "OIDCClientSecretRequest")

				metadataMap, ok := yamlObj["metadata"].(map[string]any)
				require.True(t, ok, "metadata should be a map")
				require.Len(t, metadataMap, 3, "metadata should contain only 3 keys (creationTimestamp, name, namespace): %v", metadataMap)
				require.Equal(t, metadataMap["name"], oidcClientName)
				require.Equal(t, metadataMap["namespace"], env.SupervisorNamespace)

				timestamp, ok := metadataMap["creationTimestamp"].(string)
				require.Truef(t, ok, "timestamp should be a string: %v", timestamp)
				parsedTime, err := time.Parse(time.RFC3339, timestamp)
				require.NoError(t, err)
				testutil.RequireTimeInDelta(t, parsedTime, time.Now(), 1*time.Minute)

				specMap, ok := yamlObj["spec"].(map[string]any)
				require.True(t, ok, "spec should be a map")
				require.Len(t, specMap, 2, "spec should contain only 2 keys (generateNewSecret, revokeOldSecrets): %v", specMap)
				require.Equal(t, specMap["generateNewSecret"], true)
				require.Equal(t, specMap["revokeOldSecrets"], false)

				statusMap, ok := yamlObj["status"].(map[string]any)
				require.True(t, ok, "status should be a map")
				require.Len(t, specMap, 2, "status should contain only 2 keys (generatedSecret, totalClientSecrets): %v", statusMap)
				require.Regexp(t, "^[0-9a-z]{64}$", statusMap["generatedSecret"], "generated secret must be precisely 40 hex encoded characters")
				require.Equal(t, statusMap["totalClientSecrets"], float64(1))
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				requireCleanKubectlStderr(t, stdErrString)
			},
		},
		{
			name: "kubectl get oidcclientsecretrequest should return an empty list",
			oicClientSecretRequestYAML: func(s string) string {
				return ``
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"get", "oidcclientsecretrequest", "-n", env.SupervisorNamespace}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				require.Empty(t, stdOutString)
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				require.Contains(t, stdErrString, fmt.Sprintf("No resources found in %s namespace.", env.SupervisorNamespace))
			},
		},
		{
			name: "kubectl delete oidcclientsecretrequest will return a not found error",
			oicClientSecretRequestYAML: func(name string) string {
				return here.Docf(`
					apiVersion: clientsecret.supervisor.%s/v1alpha1
					kind: OIDCClientSecretRequest
					metadata:
					  name: %s
					  namespace: %s
				`, env.APIGroupSuffix, name, env.SupervisorNamespace)
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"delete", "-f", filePath}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				require.Empty(t, stdOutString)
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				require.Contains(t, stdErrString, fmt.Sprintf("Error from server (NotFound): error when deleting \"%s\": the server could not find the requested resource\n", tempFileName))
			},
			wantErr: `exit status 1`,
		},
		{
			name: "kubectl create oidcclientsecretrequest with bad data (incorrect namespace: concierge instead of supervisor) will return an error with a reasonable formatting",
			oicClientSecretRequestYAML: func(name string) string {
				return here.Docf(`
					apiVersion: clientsecret.supervisor.%s/v1alpha1
					kind: OIDCClientSecretRequest
					metadata:
					  name: %s
					  namespace: %s
					spec:
					  generateNewSecret: true
					  revokeOldSecrets: false
				`, env.APIGroupSuffix, name, env.ConciergeNamespace)
			},
			cmdInvocation: func(filePath string) []string {
				return []string{"create", "-f", filePath, "-o", "yaml"}
			},
			assertOnStdOut: func(t *testing.T, oidcClientName string, stdOutString string) {
				require.Equal(t, "", stdOutString)
			},
			assertOnStdErr: func(t *testing.T, oidcClientName, tempFileName, stdErrString string) {
				require.Contains(t, stdErrString, fmt.Sprintf(
					`Error from server (BadRequest): error when creating "%s": namespace must be %s on OIDCClientSecretRequest, was %s`,
					tempFileName, env.SupervisorNamespace, env.ConciergeNamespace),
				)
			},
			wantErr: `exit status 1`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 13*time.Minute)
			t.Cleanup(cancel)

			supervisorClient := testlib.NewSupervisorClientset(t)

			oidcClient, err := supervisorClient.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace).Create(ctx,
				&supervisorconfigv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "client.oauth.pinniped.dev-",
					},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
							"https://example.com",
							"http://127.0.0.1/yoyo",
						},
						AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
							"authorization_code",
							"refresh_token",
							"urn:ietf:params:oauth:grant-type:token-exchange",
						},
						AllowedScopes: []supervisorconfigv1alpha1.Scope{
							"openid",
							"offline_access",
							"username",
							"groups",
							"pinniped:request-audience",
						},
					},
				},
				metav1.CreateOptions{},
			)
			t.Cleanup(func() {
				err := supervisorClient.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace).Delete(ctx, oidcClient.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			})
			require.NoError(t, err)

			clientSecretRequestYAML := tt.oicClientSecretRequestYAML(oidcClient.Name)
			secretReqFile := testutil.WriteStringToTempFile(t, "clientsecretrequest-*.yaml", clientSecretRequestYAML)

			//nolint:gosec // not worried about these potentially tainted inputs
			cmd := exec.CommandContext(ctx, "kubectl", tt.cmdInvocation(secretReqFile.Name())...)
			var stdOut, stdErr bytes.Buffer
			cmd.Stdout = &stdOut
			cmd.Stderr = &stdErr

			err = cmd.Run()

			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			tt.assertOnStdOut(t, oidcClient.Name, stdOut.String())
			tt.assertOnStdErr(t, oidcClient.Name, secretReqFile.Name(), stdErr.String())
		})
	}
}

func TestCreateOIDCClientSecretRequest_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	type testRequest struct {
		secretRequest   *clientsecretv1alpha1.OIDCClientSecretRequest
		wantSecretCount int
		wantErr         func(string) string
	}
	type StoredClientSecret struct {
		SecretHashes []string `json:"hashes"`
		Version      string   `json:"version"`
	}

	tests := []struct {
		name                 string
		clientSecretRequests func(name string) []testRequest
	}{
		{
			name: "create 1st client secret",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "create 2 client secrets, count increases to 2",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
								RevokeOldSecrets:  false,
							},
						},
						wantSecretCount: 2,
					},
				}
			},
		},
		{
			name: "create 2nd client secret, revoke original client secret, storage secret should count remains 1",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "when no secret exists, revoking without generating results in noop without errors",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 0,
					},
				}
			},
		},
		{
			name: "when no secret exists, not generating and not revoking results in noop without errors",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  false,
							},
						},
						wantSecretCount: 0,
					},
				}
			},
		},
		{
			name: "having created a first secret, do not generate a new secret and do not revoke old secrets results in noop without errors",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  false,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "having created a first secret, on a 2nd request do not create a new secret but also revoke old secrets, result is existing secret remains (safety net, disallow deletion of final secret)",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "having created a first secret, on a 2nd request that creates a new secret and also revoke old secrets, result is a single new client secret",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "having created a first client secret, on subsequent secret requests (up to 5) stored secret hashes should increase, " +
				"and when a sixth secret request is made which revokes all old secrets, the result will be one final new secret hash",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 2,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 3,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 4,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 5,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "having created a first client secret, on subsequent secret requests (up to 5) stored secret hashes should increase, " +
				"and when a sixth secret request is made without creating a new client secret but revoking all old secrets, the result " +
				"will be that the last created secret will remain (safety net)",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 2,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 3,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 4,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 5,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 1,
					},
				}
			},
		},
		{
			name: "having already created 5 client secrets, generating a 5th secret should error when revokeOldSecrets is false",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 1,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 2,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 3,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 4,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 5,
					},
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: env.SupervisorNamespace,
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
								RevokeOldSecrets:  false,
							},
						},
						wantSecretCount: 5,
						wantErr: func(name string) string {
							return fmt.Sprintf("OIDCClient %s has too many secrets, spec.revokeOldSecrets must be true", name)
						},
					},
				}
			},
		},
		{
			name: "generateName is unsupported on OIDCClientSecretRequest objects",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								GenerateName: "some-generate-name-prefix-",
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 0,
						wantErr: func(name string) string {
							return fmt.Sprintf(
								`OIDCClientSecretRequest.clientsecret.supervisor.%s "" is invalid: [metadata.generateName: Invalid value: "some-generate-name-prefix-": generateName is not supported, metadata.name: Required value: name or generateName is required]`,
								env.APIGroupSuffix)
						},
					},
				}
			},
		},
		{
			name: "name must not equal client.oauth.pinniped.dev-",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name: "client.oauth.pinniped.dev-",
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 0,
						wantErr: func(name string) string {
							return fmt.Sprintf(
								`OIDCClientSecretRequest.clientsecret.supervisor.%s "client.oauth.pinniped.dev-" is invalid: metadata.name: Invalid value: "client.oauth.pinniped.dev-": must not equal 'client.oauth.pinniped.dev-'`,
								env.APIGroupSuffix)
						},
					},
				}
			},
		},
		{
			name: "name must contain client.oauth.pinniped.dev-",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name: "doesnt-contain-prefix",
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 0,
						wantErr: func(name string) string {
							return fmt.Sprintf(
								`OIDCClientSecretRequest.clientsecret.supervisor.%s "doesnt-contain-prefix" is invalid: metadata.name: Invalid value: "doesnt-contain-prefix": must start with 'client.oauth.pinniped.dev-'`,
								env.APIGroupSuffix)
						},
					},
				}
			},
		},
		{
			name: "namespace on the OIDCClientSecretRequest object does not match the namespace on the associated OIDCClient",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name:      name,
								Namespace: "some-other-namespace",
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: true,
							},
						},
						wantSecretCount: 0,
						wantErr: func(name string) string {
							return `the namespace of the provided object does not match the namespace sent on the request`
						},
					},
				}
			},
		},
		{
			name: "client secret request created for an oidc client that does not exist should error",
			clientSecretRequests: func(name string) []testRequest {
				return []testRequest{
					{
						secretRequest: &clientsecretv1alpha1.OIDCClientSecretRequest{
							ObjectMeta: metav1.ObjectMeta{
								Name: "client.oauth.pinniped.dev-client-that-does-not-exist",
							},
							Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
								GenerateNewSecret: false,
								RevokeOldSecrets:  true,
							},
						},
						wantSecretCount: 0,
						wantErr: func(name string) string {
							return fmt.Sprintf(
								`OIDCClientSecretRequest.clientsecret.supervisor.%s "client.oauth.pinniped.dev-client-that-does-not-exist" is invalid: metadata.name: Not found: "client.oauth.pinniped.dev-client-that-does-not-exist"`,
								env.APIGroupSuffix)
						},
					},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 13*time.Minute)
			t.Cleanup(cancel)

			kubeClient := testlib.NewKubernetesClientset(t)
			supervisorClient := testlib.NewSupervisorClientset(t)

			oidcClient, err := supervisorClient.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace).Create(ctx,
				&supervisorconfigv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "client.oauth.pinniped.dev-",
					},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
							"https://example.com",
							"http://127.0.0.1/yoyo",
						},
						AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
							"authorization_code",
							"refresh_token",
							"urn:ietf:params:oauth:grant-type:token-exchange",
						},
						AllowedScopes: []supervisorconfigv1alpha1.Scope{
							"openid",
							"offline_access",
							"username",
							"groups",
							"pinniped:request-audience",
						},
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				cleanupCtx, cleanupCtxCancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cleanupCtxCancel()
				deleteErr := supervisorClient.ConfigV1alpha1().
					OIDCClients(env.SupervisorNamespace).Delete(cleanupCtx, oidcClient.Name, metav1.DeleteOptions{})
				require.NoError(t, deleteErr)
				testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
					_, err := kubeClient.CoreV1().Secrets(oidcClient.Namespace).
						Get(cleanupCtx, oidcclientsecretstorage.New(nil).GetName(oidcClient.UID), metav1.GetOptions{})
					requireEventually.Error(err, "deleting OIDCClient should result in deleting storage secrets")
					requireEventually.True(apierrors.IsNotFound(err),
						"deleting OIDCClient should result in deleting storage secrets")
				}, 2*time.Minute, 250*time.Millisecond)
			})

			type memoKey struct {
				storedSecretHash, plaintextPassword string
			}
			cacheOfGeneratedSecrets := []string{}
			hasSecretBeenGenerated := false
			memoizedBcryptHashes := map[memoKey]bool{}
			for n, ttt := range tt.clientSecretRequests(oidcClient.Name) {
				clientSecretRequestResponse, err := supervisorClient.ClientsecretV1alpha1().
					OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx, ttt.secretRequest, metav1.CreateOptions{})

				if ttt.wantErr != nil { //nolint:nestif
					require.EqualError(t, err, ttt.wantErr(oidcClient.Name))
				} else {
					require.NoError(t, err)

					require.Equal(t, ttt.secretRequest.Name, clientSecretRequestResponse.Name,
						"name in response should match name in sent request")
					require.Equal(t, ttt.secretRequest.Namespace, clientSecretRequestResponse.Namespace,
						"namespace in response should match namespace in sent request")
					testutil.RequireTimeInDelta(t, clientSecretRequestResponse.CreationTimestamp.Time, time.Now(), 1*time.Minute)

					require.Equalf(t, ttt.secretRequest.TypeMeta, clientSecretRequestResponse.TypeMeta,
						"type meta of response should match the sent request")

					require.Equalf(t, ttt.secretRequest.Spec, clientSecretRequestResponse.Spec,
						"spec of response should match the sent request")

					require.Equalf(t, clientSecretRequestResponse.Status.TotalClientSecrets, ttt.wantSecretCount,
						"expected secret count is incorrect on iteration %d", n)

					if ttt.secretRequest.Spec.GenerateNewSecret {
						require.Len(t, clientSecretRequestResponse.Status.GeneratedSecret, hex.EncodedLen(32),
							"generated secret is not a hex encoded string")
					} else {
						require.Empty(t, clientSecretRequestResponse.Status.GeneratedSecret,
							"when GenerateSecret is false no secret should be generated")
					}

					// api will not let you revoke your last secret unless you are also generating a new secret
					if ttt.secretRequest.Spec.RevokeOldSecrets {
						if ttt.secretRequest.Spec.GenerateNewSecret {
							// we will add the newly generated secret below
							cacheOfGeneratedSecrets = []string{}
						} else {
							// if we aren't creating a new secret, we need to keep the most recent secret
							cacheOfGeneratedSecrets = retainOnlyMostRecentSecret(cacheOfGeneratedSecrets)
						}
					}

					if ttt.secretRequest.Spec.GenerateNewSecret {
						cacheOfGeneratedSecrets = prependSecret(cacheOfGeneratedSecrets, clientSecretRequestResponse.Status.GeneratedSecret)
						hasSecretBeenGenerated = true
					}

					require.Len(t, cacheOfGeneratedSecrets, ttt.wantSecretCount,
						"number of generated secrets should match number of hashed secrets")
				}

				// even if we got an error, we want to get the storage secret and make assertions about its state
				storageSecret, getStorageSecretError := kubeClient.CoreV1().Secrets(oidcClient.Namespace).
					Get(ctx, oidcclientsecretstorage.New(nil).GetName(oidcClient.UID), metav1.GetOptions{})
				if !hasSecretBeenGenerated {
					require.Error(t, getStorageSecretError, "expected not found error")
					require.True(t, apierrors.IsNotFound(getStorageSecretError), "expected not found error")
					// no storage secret was created, so no reason to continue making assertions
					continue
				}
				require.NoError(t, getStorageSecretError)

				storedClientSecret := StoredClientSecret{}
				err = json.Unmarshal(storageSecret.Data["pinniped-storage-data"], &storedClientSecret)
				require.NoError(t, err)

				require.Len(t, storedClientSecret.SecretHashes, ttt.wantSecretCount)

				for i, storedSecretHash := range storedClientSecret.SecretHashes {
					plaintextSecret := cacheOfGeneratedSecrets[i]
					// Calling bcrypt.CompareHashAndPassword is very expensive. If this loop has already called
					// bcrypt.CompareHashAndPassword with the exact same inputs, then don't call it again.
					mKey := memoKey{storedSecretHash: storedSecretHash, plaintextPassword: plaintextSecret}
					if !memoizedBcryptHashes[mKey] {
						require.NoErrorf(t, bcrypt.CompareHashAndPassword([]byte(storedSecretHash), []byte(plaintextSecret)),
							"hash %q at index %d is not the hash of secret %q at (%s)", storedSecretHash, i, plaintextSecret)
						memoizedBcryptHashes[mKey] = true // remember that we already successfully confirmed these params to CompareHashAndPassword
					}
				}
			}
		})
	}
}

func retainOnlyMostRecentSecret(list []string) []string {
	if len(list) == 0 {
		return []string{}
	}
	return []string{list[0]}
}

func prependSecret(list []string, newItem string) []string {
	return slices.Concat([]string{newItem}, list)
}

func TestOIDCClientSecretRequestUnauthenticated_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	client := testlib.NewAnonymousSupervisorClientset(t)

	_, err := client.ClientsecretV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&clientsecretv1alpha1.OIDCClientSecretRequest{
			Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
			},
		}, metav1.CreateOptions{})
	require.Error(t, err)

	if env.KubernetesDistribution == testlib.AKSDistro {
		// On AKS the error just says "Unauthorized".
		require.Contains(t, err.Error(), "Unauthorized")
	} else {
		// Clusters which allow anonymous auth will give a more detailed error.
		require.Contains(t, err.Error(), `User "system:anonymous" cannot create resource "oidcclientsecretrequests"`)
	}
}
