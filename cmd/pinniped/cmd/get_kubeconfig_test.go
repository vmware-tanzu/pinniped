// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	coretesting "k8s.io/client-go/testing"

	authv1alpha "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/here"
)

var (
	knownGoodUsageForGetKubeConfig = here.Doc(`
		Usage:
		  get-kubeconfig [flags]

		Flags:
			  --authenticator-name string   Authenticator name
			  --authenticator-type string   Authenticator type (e.g., 'webhook')
		  -h, --help                        help for get-kubeconfig
			  --kubeconfig string           Path to the kubeconfig file
			  --kubeconfig-context string   Kubeconfig context override
			  --pinniped-namespace string   Namespace in which Pinniped was installed (default "pinniped-concierge")
			  --token string                Credential to include in the resulting kubeconfig output (Required)

		`)

	knownGoodHelpForGetKubeConfig = here.Doc(`
		Print a kubeconfig for authenticating into a cluster via Pinniped.

		Requires admin-like access to the cluster using the current
		kubeconfig context in order to access Pinniped's metadata.
		The current kubeconfig is found similar to how kubectl finds it:
		using the value of the --kubeconfig option, or if that is not
		specified then from the value of the KUBECONFIG environment
		variable, or if that is not specified then it defaults to
		.kube/config in your home directory.

		Prints a kubeconfig which is suitable to access the cluster using
		Pinniped as the authentication mechanism. This kubeconfig output
		can be saved to a file and used with future kubectl commands, e.g.:
			pinniped get-kubeconfig --token $MY_TOKEN > $HOME/mycluster-kubeconfig
			kubectl --kubeconfig $HOME/mycluster-kubeconfig get pods

		Usage:
		  get-kubeconfig [flags]

		Flags:
			  --authenticator-name string   Authenticator name
			  --authenticator-type string   Authenticator type (e.g., 'webhook')
		  -h, --help                        help for get-kubeconfig
			  --kubeconfig string           Path to the kubeconfig file
			  --kubeconfig-context string   Kubeconfig context override
			  --pinniped-namespace string   Namespace in which Pinniped was installed (default "pinniped-concierge")
			  --token string                Credential to include in the resulting kubeconfig output (Required)
		`)
)

func TestNewGetKubeConfigCmd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantError  bool
		wantStdout string
		wantStderr string
	}{
		{
			name:       "help flag passed",
			args:       []string{"--help"},
			wantStdout: knownGoodHelpForGetKubeConfig,
		},
		{
			name:       "missing required flag",
			args:       []string{},
			wantError:  true,
			wantStdout: `Error: required flag(s) "token" not set` + "\n" + knownGoodUsageForGetKubeConfig,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := newGetKubeConfigCommand().Command()
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantStdout, stdout.String(), "unexpected stdout")
			require.Equal(t, tt.wantStderr, stderr.String(), "unexpected stderr")
		})
	}
}

type expectedKubeconfigYAML struct {
	clusterCAData     string
	clusterServer     string
	command           string
	token             string
	pinnipedEndpoint  string
	pinnipedCABundle  string
	namespace         string
	authenticatorType string
	authenticatorName string
}

func (e expectedKubeconfigYAML) String() string {
	return here.Docf(`
		apiVersion: v1
		clusters:
		- cluster:
			certificate-authority-data: %s
			server: %s
		  name: pinniped-cluster
		contexts:
		- context:
			cluster: pinniped-cluster
			user: pinniped-user
		  name: pinniped-cluster
		current-context: pinniped-cluster
		kind: Config
		preferences: {}
		users:
		- name: pinniped-user
		  user:
			exec:
			  apiVersion: client.authentication.k8s.io/v1beta1
			  args:
			  - exchange-credential
			  command: %s
			  env:
			  - name: PINNIPED_K8S_API_ENDPOINT
				value: %s
			  - name: PINNIPED_CA_BUNDLE
				value: %s
			  - name: PINNIPED_NAMESPACE
			    value: %s
			  - name: PINNIPED_TOKEN
				value: %s
			  - name: PINNIPED_AUTHENTICATOR_TYPE
				value: %s
			  - name: PINNIPED_AUTHENTICATOR_NAME
				value: %s
			  installHint: |-
				The Pinniped CLI is required to authenticate to the current cluster.
				For more information, please visit https://pinniped.dev
		`, e.clusterCAData, e.clusterServer, e.command, e.pinnipedEndpoint, e.pinnipedCABundle, e.namespace, e.token, e.authenticatorType, e.authenticatorName)
}

func newCredentialIssuer(name, namespace, server, certificateAuthorityData string) *configv1alpha1.CredentialIssuer {
	return &configv1alpha1.CredentialIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CredentialIssuer",
			APIVersion: configv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: configv1alpha1.CredentialIssuerStatus{
			KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
				Server:                   server,
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(certificateAuthorityData)),
			},
		},
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		mocks      func(*getKubeConfigCommand)
		wantError  string
		wantStdout string
		wantStderr string
	}{
		{
			name: "failure to get path to self",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.getPathToSelf = func() (string, error) {
					return "", fmt.Errorf("some error getting path to self")
				}
			},
			wantError: "could not find path to self: some error getting path to self",
		},
		{
			name: "kubeconfig does not exist",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.flags.kubeconfig = "./testdata/does-not-exist.yaml"
			},
			wantError: "stat ./testdata/does-not-exist.yaml: no such file or directory",
		},
		{
			name: "fail to get client",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return nil, fmt.Errorf("some error configuring clientset")
				}
			},
			wantError: "some error configuring clientset",
		},
		{
			name: "fail to get authenticators",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.flags.authenticatorName = ""
				cmd.flags.authenticatorType = ""
				clientset := pinnipedfake.NewSimpleClientset()
				clientset.PrependReactor("*", "*", func(_ coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("some error getting authenticators")
				})
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return clientset, nil
				}
			},
			wantError: "some error getting authenticators",
		},
		{
			name: "zero authenticators",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.flags.authenticatorName = ""
				cmd.flags.authenticatorType = ""
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(), nil
				}
			},
			wantError: `no authenticators were found in namespace "test-namespace"`,
		},
		{
			name: "multiple authenticators",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.flags.authenticatorName = ""
				cmd.flags.authenticatorType = ""
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(
						&authv1alpha.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "webhook-one"}},
						&authv1alpha.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "webhook-two"}},
					), nil
				}
			},
			wantError: `multiple authenticators were found in namespace "test-namespace", so --authenticator-name/--authenticator-type must be specified`,
		},
		{
			name: "fail to get CredentialIssuers",
			mocks: func(cmd *getKubeConfigCommand) {
				clientset := pinnipedfake.NewSimpleClientset()
				clientset.PrependReactor("*", "*", func(_ coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("some error getting CredentialIssuers")
				})
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return clientset, nil
				}
			},
			wantError: "some error getting CredentialIssuers",
		},
		{
			name: "zero CredentialIssuers found",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(
						newCredentialIssuer("pinniped-config-1", "not-the-test-namespace", "", ""),
					), nil
				}
			},
			wantError: `No CredentialIssuer was found in namespace "test-namespace". Is Pinniped installed on this cluster in namespace "test-namespace"?`,
		},
		{
			name: "multiple CredentialIssuers found",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(
						newCredentialIssuer("pinniped-config-1", "test-namespace", "", ""),
						newCredentialIssuer("pinniped-config-2", "test-namespace", "", ""),
					), nil
				}
			},
			wantError: `More than one CredentialIssuer was found in namespace "test-namespace"`,
		},
		{
			name: "CredentialIssuer missing KubeConfigInfo",
			mocks: func(cmd *getKubeConfigCommand) {
				ci := newCredentialIssuer("pinniped-config", "test-namespace", "", "")
				ci.Status.KubeConfigInfo = nil
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(ci), nil
				}
			},
			wantError: `CredentialIssuer "pinniped-config" was missing KubeConfigInfo`,
		},
		{
			name: "KubeConfigInfo has invalid base64",
			mocks: func(cmd *getKubeConfigCommand) {
				ci := newCredentialIssuer("pinniped-config", "test-namespace", "https://example.com", "")
				ci.Status.KubeConfigInfo.CertificateAuthorityData = "invalid-base64-test-ca"
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(ci), nil
				}
			},
			wantError: `illegal base64 data at input byte 7`,
		},
		{
			name: "success using remote CA data",
			mocks: func(cmd *getKubeConfigCommand) {
				ci := newCredentialIssuer("pinniped-config", "test-namespace", "https://fake-server-url-value", "fake-certificate-authority-data-value")
				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(ci), nil
				}
			},
			wantStdout: expectedKubeconfigYAML{
				clusterCAData:     "ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==",
				clusterServer:     "https://fake-server-url-value",
				command:           "/path/to/pinniped",
				token:             "test-token",
				pinnipedEndpoint:  "https://fake-server-url-value",
				pinnipedCABundle:  "fake-certificate-authority-data-value",
				namespace:         "test-namespace",
				authenticatorType: "test-authenticator-type",
				authenticatorName: "test-authenticator-name",
			}.String(),
		},
		{
			name: "success using local CA data and discovered authenticator",
			mocks: func(cmd *getKubeConfigCommand) {
				cmd.flags.authenticatorName = ""
				cmd.flags.authenticatorType = ""

				cmd.kubeClientCreator = func(_ *rest.Config) (pinnipedclientset.Interface, error) {
					return pinnipedfake.NewSimpleClientset(
						&authv1alpha.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "discovered-authenticator"}},
						newCredentialIssuer("pinniped-config", "test-namespace", "https://example.com", "test-ca"),
					), nil
				}
			},
			wantStderr: `WARNING: Server and certificate authority did not match between local kubeconfig and Pinniped's CredentialIssuer on the cluster. Using local kubeconfig values.`,
			wantStdout: expectedKubeconfigYAML{
				clusterCAData:     "ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==",
				clusterServer:     "https://fake-server-url-value",
				command:           "/path/to/pinniped",
				token:             "test-token",
				pinnipedEndpoint:  "https://fake-server-url-value",
				pinnipedCABundle:  "fake-certificate-authority-data-value",
				namespace:         "test-namespace",
				authenticatorType: "webhook",
				authenticatorName: "discovered-authenticator",
			}.String(),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Start with a default getKubeConfigCommand, set some defaults, then apply any mocks.
			c := newGetKubeConfigCommand()
			c.flags.token = "test-token"
			c.flags.namespace = "test-namespace"
			c.flags.authenticatorName = "test-authenticator-name"
			c.flags.authenticatorType = "test-authenticator-type"
			c.getPathToSelf = func() (string, error) { return "/path/to/pinniped", nil }
			c.flags.kubeconfig = "./testdata/kubeconfig.yaml"
			tt.mocks(c)

			cmd := &cobra.Command{}
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs([]string{})
			err := c.run(cmd, []string{})
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, strings.TrimSpace(tt.wantStdout), strings.TrimSpace(stdout.String()), "unexpected stdout")
			require.Equal(t, strings.TrimSpace(tt.wantStderr), strings.TrimSpace(stderr.String()), "unexpected stderr")
		})
	}
}
