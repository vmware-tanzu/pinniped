// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"

	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/here"
)

func TestWhoami(t *testing.T) {
	helpOutputFormatString := here.Doc(`
		Print information about the current user

		Usage:
		  whoami [flags]

		Flags:
			  --api-group-suffix string     Concierge API group suffix (default "pinniped.dev")
		  -h, --help                        help for whoami
			  --kubeconfig string           Path to kubeconfig file%s
			  --kubeconfig-context string   Kubeconfig context name (default: current active context)
		  -o, --output string               Output format (e.g., 'yaml', 'json', 'text') (default "text")
			  --timeout duration            Timeout for the WhoAmI API request (default: 0, meaning no timeout)
	`)

	tests := []struct {
		name                   string
		args                   []string
		env                    map[string]string
		groupsOverride         []string
		gettingClientsetErr    error
		callingAPIErr          error
		wantError              bool
		wantStdout, wantStderr string
	}{
		{
			name:       "help flag passed",
			args:       []string{"--help"},
			wantStdout: fmt.Sprintf(helpOutputFormatString, ""),
		},
		{
			name: "help flag passed with KUBECONFIG env var set",
			env: map[string]string{
				"KUBECONFIG": "/path/to/kubeconfig",
			},
			args:       []string{"--help"},
			wantStdout: fmt.Sprintf(helpOutputFormatString, ` (default "/path/to/kubeconfig")`),
		},
		{
			name: "text output",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml"},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: kind-cluster
				URL: https://fake-server-url-value

				Current user info:

				Username: some-username
				Groups: some-group-0, some-group-1
			`),
		},
		{
			name: "text output with long output flag",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml", "--output", "text"},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: kind-cluster
				URL: https://fake-server-url-value

				Current user info:

				Username: some-username
				Groups: some-group-0, some-group-1
			`),
		},
		{
			name:           "text output with 1 group",
			args:           []string{"--kubeconfig", "testdata/kubeconfig.yaml", "--output", "text"},
			groupsOverride: []string{"some-group-0"},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: kind-cluster
				URL: https://fake-server-url-value

				Current user info:

				Username: some-username
				Groups: some-group-0
			`),
		},
		{
			name:           "text output with no groups",
			args:           []string{"--kubeconfig", "testdata/kubeconfig.yaml", "--output", "text"},
			groupsOverride: []string{},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: kind-cluster
				URL: https://fake-server-url-value

				Current user info:

				Username: some-username
				Groups:` + " \n"), // Linters and codeformatters don't like the extra space after "Groups:" and before the newline
		},
		{
			name: "json output",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml", "-o", "json"},
			wantStdout: here.Doc(`
				{
				  "kind": "WhoAmIRequest",
				  "apiVersion": "identity.concierge.pinniped.dev/v1alpha1",
				  "metadata": {
				    "creationTimestamp": null
				  },
				  "spec": {},
				  "status": {
				    "kubernetesUserInfo": {
				      "user": {
				        "username": "some-username",
				        "groups": [
				          "some-group-0",
				          "some-group-1"
				        ]
				      }
				    }
				  }
				}`),
		},
		{
			name: "json output with api group suffix flag",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml", "-o", "json", "--api-group-suffix", "tuna.io"},
			wantStdout: here.Doc(`
				{
				  "kind": "WhoAmIRequest",
				  "apiVersion": "identity.concierge.tuna.io/v1alpha1",
				  "metadata": {
				    "creationTimestamp": null
				  },
				  "spec": {},
				  "status": {
				    "kubernetesUserInfo": {
				      "user": {
				        "username": "some-username",
				        "groups": [
				          "some-group-0",
				          "some-group-1"
				        ]
				      }
				    }
				  }
				}`),
		},
		{
			name: "yaml output",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml", "-o", "yaml"},
			wantStdout: here.Doc(`
				apiVersion: identity.concierge.pinniped.dev/v1alpha1
				kind: WhoAmIRequest
				metadata:
				  creationTimestamp: null
				spec: {}
				status:
				  kubernetesUserInfo:
				    user:
				      groups:
				      - some-group-0
				      - some-group-1
				      username: some-username
			`),
		},
		{
			name: "yaml output with api group suffix",
			args: []string{"--kubeconfig", "testdata/kubeconfig.yaml", "-o", "yaml", "--api-group-suffix", "tuna.io"},
			wantStdout: here.Doc(`
				apiVersion: identity.concierge.tuna.io/v1alpha1
				kind: WhoAmIRequest
				metadata:
				  creationTimestamp: null
				spec: {}
				status:
				  kubernetesUserInfo:
				    user:
				      groups:
				      - some-group-0
				      - some-group-1
				      username: some-username
			`),
		},
		{
			name:       "extra args",
			args:       []string{"extra-arg"},
			wantError:  true,
			wantStderr: "Error: unknown command \"extra-arg\" for \"whoami\"\n",
		},
		{
			name:       "cannot get cluster info",
			args:       []string{"--kubeconfig", "this-file-does-not-exist"},
			wantError:  true,
			wantStderr: "Error: could not get current cluster info: stat this-file-does-not-exist: no such file or directory\n",
		},
		{
			name: "different kubeconfig context, but same as current",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--kubeconfig-context", "kind-context",
			},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: kind-cluster
				URL: https://fake-server-url-value

				Current user info:

				Username: some-username
				Groups: some-group-0, some-group-1
			`),
		},
		{
			name: "different kubeconfig context, not current",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--kubeconfig-context", "some-other-context",
			},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: some-other-cluster
				URL: https://some-other-fake-server-url-value

				Current user info:

				Username: some-username
				Groups: some-group-0, some-group-1
			`),
		},
		{
			name: "invalid kubeconfig context prints ???",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--kubeconfig-context", "invalid",
			},
			wantStdout: here.Doc(`
				Current cluster info:

				Name: ???
				URL: ???

				Current user info:

				Username: some-username
				Groups: some-group-0, some-group-1
			`),
		},
		{
			name:                "getting clientset fails",
			gettingClientsetErr: constable.Error("some get clientset error"),
			wantError:           true,
			wantStderr:          "Error: could not configure Kubernetes client: some get clientset error\n",
		},
		{
			name:          "calling API fails",
			callingAPIErr: constable.Error("some API error"),
			wantError:     true,
			wantStderr:    "Error: could not complete WhoAmIRequest: some API error\n",
		},
		{
			name:          "calling API fails because WhoAmI API is not installed",
			callingAPIErr: apierrors.NewNotFound(identityv1alpha1.SchemeGroupVersion.WithResource("whoamirequests").GroupResource(), "whatever"),
			wantError:     true,
			wantStderr:    "Error: could not complete WhoAmIRequest (is the Pinniped WhoAmI API running and healthy?): whoamirequests.identity.concierge.pinniped.dev \"whatever\" not found\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getClientset := func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error) {
				if test.gettingClientsetErr != nil {
					return nil, test.gettingClientsetErr
				}
				clientset := conciergefake.NewSimpleClientset()
				clientset.PrependReactor("create", "whoamirequests", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					if test.callingAPIErr != nil {
						return true, nil, test.callingAPIErr
					}
					groups := []string{"some-group-0", "some-group-1"}
					if test.groupsOverride != nil {
						groups = test.groupsOverride
					}
					return true, &identityv1alpha1.WhoAmIRequest{
						Status: identityv1alpha1.WhoAmIRequestStatus{
							KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
								User: identityv1alpha1.UserInfo{
									Username: "some-username",
									Groups:   groups,
								},
							},
						},
					}, nil
				})
				return clientset, nil
			}
			cmd := newWhoamiCommand(whoamiDeps{
				getenv: func(key string) string {
					return test.env[key]
				},
				getClientset: getClientset,
			})

			stdout, stderr := bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{})
			cmd.SetOut(stdout)
			cmd.SetErr(stderr)
			if test.args == nil {
				// cobra uses os.Args[1:] when SetArgs is called with nil, so avoid using nil for tests.
				cmd.SetArgs([]string{})
			} else {
				cmd.SetArgs(test.args)
			}

			err := cmd.Execute()
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.wantStdout, stdout.String())
			require.Equal(t, test.wantStderr, stderr.String())
		})
	}
}
