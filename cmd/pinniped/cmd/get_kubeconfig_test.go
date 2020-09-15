/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/crdpinniped/v1alpha1"
	pinnipedclientset "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned"
	pinnipedfake "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned/fake"
	"github.com/suzerain-io/pinniped/internal/here"
)

// TODO write a test for the help message and command line flags similar to server_test.go

func expectedKubeconfigYAML(clusterCAData, clusterServer, command, token, pinnipedEndpoint, pinnipedCABundle string) string {
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
			  - name: PINNIPED_TOKEN
				value: %s
			  installHint: |-
				The Pinniped CLI is required to authenticate to the current cluster.
				For more information, please visit https://pinniped.dev
		`, clusterCAData, clusterServer, command, pinnipedEndpoint, pinnipedCABundle, token)
}

func newCredentialIssuerConfig(server, certificateAuthorityData string) *crdpinnipedv1alpha1.CredentialIssuerConfig {
	return &crdpinnipedv1alpha1.CredentialIssuerConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CredentialIssuerConfig",
			APIVersion: crdpinnipedv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pinniped-config",
			Namespace: "some-namespace",
		},
		Status: crdpinnipedv1alpha1.CredentialIssuerConfigStatus{
			KubeConfigInfo: &crdpinnipedv1alpha1.CredentialIssuerConfigKubeConfigInfo{
				Server:                   server,
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(certificateAuthorityData)),
			},
		},
	}
}

func TestGetKubeConfig(t *testing.T) {
	spec.Run(t, "cmd.getKubeConfig", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var outputBuffer *bytes.Buffer
		var warningsBuffer *bytes.Buffer
		var fullPathToSelf string
		var pinnipedClient *pinnipedfake.Clientset

		it.Before(func() {
			r = require.New(t)

			outputBuffer = new(bytes.Buffer)
			warningsBuffer = new(bytes.Buffer)

			var err error
			fullPathToSelf, err = os.Executable()
			r.NoError(err)

			pinnipedClient = pinnipedfake.NewSimpleClientset()
		})

		when("the CredentialIssuerConfig is found on the cluster with a configuration that matches the existing kubeconfig", func() {
			it.Before(func() {
				r.NoError(pinnipedClient.Tracker().Add(
					newCredentialIssuerConfig("https://fake-server-url-value", "fake-certificate-authority-data-value"),
				))
			})

			it("writes the kubeconfig to the given writer", func() {
				kubeClientCreatorFuncWasCalled := false
				err := getKubeConfig(outputBuffer,
					warningsBuffer,
					"some-token",
					"./testdata/kubeconfig.yaml",
					"",
					"some-namespace",
					func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
						kubeClientCreatorFuncWasCalled = true
						r.Equal("https://fake-server-url-value", restConfig.Host)
						r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
						return pinnipedClient, nil
					},
				)
				r.NoError(err)
				r.True(kubeClientCreatorFuncWasCalled)

				r.Empty(warningsBuffer.String())
				r.Equal(expectedKubeconfigYAML(
					base64.StdEncoding.EncodeToString([]byte("fake-certificate-authority-data-value")),
					"https://fake-server-url-value",
					fullPathToSelf,
					"some-token",
					"https://fake-server-url-value",
					"fake-certificate-authority-data-value",
				), outputBuffer.String())
			})

			when("the currentContextOverride is used to specify a context other than the default context", func() {
				it.Before(func() {
					// update the Server and CertificateAuthorityData to make them match the other kubeconfig context
					r.NoError(pinnipedClient.Tracker().Update(
						schema.GroupVersionResource{
							Group:    crdpinnipedv1alpha1.GroupName,
							Version:  crdpinnipedv1alpha1.SchemeGroupVersion.Version,
							Resource: "credentialissuerconfigs",
						},
						newCredentialIssuerConfig(
							"https://some-other-fake-server-url-value",
							"some-other-fake-certificate-authority-data-value",
						),
						"some-namespace",
					))
				})

				when("that context exists", func() {
					it("writes the kubeconfig to the given writer using the specified context", func() {
						kubeClientCreatorFuncWasCalled := false
						err := getKubeConfig(outputBuffer,
							warningsBuffer,
							"some-token",
							"./testdata/kubeconfig.yaml",
							"some-other-context",
							"some-namespace",
							func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
								kubeClientCreatorFuncWasCalled = true
								r.Equal("https://some-other-fake-server-url-value", restConfig.Host)
								r.Equal("some-other-fake-certificate-authority-data-value", string(restConfig.CAData))
								return pinnipedClient, nil
							},
						)
						r.NoError(err)
						r.True(kubeClientCreatorFuncWasCalled)

						r.Empty(warningsBuffer.String())
						r.Equal(expectedKubeconfigYAML(
							base64.StdEncoding.EncodeToString([]byte("some-other-fake-certificate-authority-data-value")),
							"https://some-other-fake-server-url-value",
							fullPathToSelf,
							"some-token",
							"https://some-other-fake-server-url-value",
							"some-other-fake-certificate-authority-data-value",
						), outputBuffer.String())
					})
				})

				when("that context does not exist the in the current kubeconfig", func() {
					it("returns an error", func() {
						err := getKubeConfig(outputBuffer,
							warningsBuffer,
							"some-token",
							"./testdata/kubeconfig.yaml",
							"this-context-name-does-not-exist-in-kubeconfig.yaml",
							"some-namespace",
							func(restConfig *rest.Config) (pinnipedclientset.Interface, error) { return pinnipedClient, nil },
						)
						r.EqualError(err, `context "this-context-name-does-not-exist-in-kubeconfig.yaml" does not exist`)
						r.Empty(warningsBuffer.String())
						r.Empty(outputBuffer.String())
					})
				})
			})

			when("the token passed in is empty", func() {
				it("returns an error", func() {
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"",
						"./testdata/kubeconfig.yaml",
						"",
						"some-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) { return pinnipedClient, nil },
					)
					r.EqualError(err, "--token flag value cannot be empty")
					r.Empty(warningsBuffer.String())
					r.Empty(outputBuffer.String())
				})
			})

			when("the kubeconfig path passed refers to a file that does not exist", func() {
				it("returns an error", func() {
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"some-token",
						"./testdata/this-file-does-not-exist.yaml",
						"",
						"some-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) { return pinnipedClient, nil },
					)
					r.EqualError(err, "stat ./testdata/this-file-does-not-exist.yaml: no such file or directory")
					r.Empty(warningsBuffer.String())
					r.Empty(outputBuffer.String())
				})
			})

			when("the kubeconfig path parameter is empty", func() {
				it.Before(func() {
					// Note that this is technically polluting other parallel tests in this file, but other tests
					// are always specifying the kubeconfigPathOverride parameter, so they're not actually looking
					// at the value of this environment variable.
					r.NoError(os.Setenv("KUBECONFIG", "./testdata/kubeconfig.yaml"))
				})

				it.After(func() {
					r.NoError(os.Unsetenv("KUBECONFIG"))
				})

				it("falls back to using the KUBECONFIG env var to find the kubeconfig file", func() {
					kubeClientCreatorFuncWasCalled := false
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"some-token",
						"",
						"",
						"some-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
							kubeClientCreatorFuncWasCalled = true
							r.Equal("https://fake-server-url-value", restConfig.Host)
							r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
							return pinnipedClient, nil
						},
					)
					r.NoError(err)
					r.True(kubeClientCreatorFuncWasCalled)

					r.Empty(warningsBuffer.String())
					r.Equal(expectedKubeconfigYAML(
						base64.StdEncoding.EncodeToString([]byte("fake-certificate-authority-data-value")),
						"https://fake-server-url-value",
						fullPathToSelf,
						"some-token",
						"https://fake-server-url-value",
						"fake-certificate-authority-data-value",
					), outputBuffer.String())
				})
			})

			when("the wrong pinniped namespace is passed in", func() {
				it("returns an error", func() {
					kubeClientCreatorFuncWasCalled := false
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"some-token",
						"./testdata/kubeconfig.yaml",
						"",
						"this-is-the-wrong-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
							kubeClientCreatorFuncWasCalled = true
							r.Equal("https://fake-server-url-value", restConfig.Host)
							r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
							return pinnipedClient, nil
						},
					)
					r.EqualError(err, `CredentialIssuerConfig "pinniped-config" was not found in namespace "this-is-the-wrong-namespace". Is Pinniped installed on this cluster in namespace "this-is-the-wrong-namespace"?`)
					r.True(kubeClientCreatorFuncWasCalled)
				})
			})
		})

		when("the CredentialIssuerConfig is found on the cluster with a configuration that does not match the existing kubeconfig", func() {
			when("the Server doesn't match", func() {
				it.Before(func() {
					r.NoError(pinnipedClient.Tracker().Add(
						newCredentialIssuerConfig("non-matching-pinniped-server-url", "fake-certificate-authority-data-value"),
					))
				})

				it("writes the kubeconfig to the given writer using the values found in the local kubeconfig and issues a warning", func() {
					kubeClientCreatorFuncWasCalled := false
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"some-token",
						"./testdata/kubeconfig.yaml",
						"",
						"some-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
							kubeClientCreatorFuncWasCalled = true
							r.Equal("https://fake-server-url-value", restConfig.Host)
							r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
							return pinnipedClient, nil
						},
					)
					r.NoError(err)
					r.True(kubeClientCreatorFuncWasCalled)

					r.Equal(
						"WARNING: Server and certificate authority did not match between local kubeconfig and Pinniped's CredentialIssuerConfig on the cluster. Using local kubeconfig values.\n",
						warningsBuffer.String(),
					)
					r.Equal(expectedKubeconfigYAML(
						base64.StdEncoding.EncodeToString([]byte("fake-certificate-authority-data-value")),
						"https://fake-server-url-value",
						fullPathToSelf,
						"some-token",
						"https://fake-server-url-value",
						"fake-certificate-authority-data-value",
					), outputBuffer.String())
				})
			})

			when("the CA doesn't match", func() {
				it.Before(func() {
					r.NoError(pinnipedClient.Tracker().Add(
						newCredentialIssuerConfig("https://fake-server-url-value", "non-matching-certificate-authority-data-value"),
					))
				})

				it("writes the kubeconfig to the given writer using the values found in the local kubeconfig and issues a warning", func() {
					kubeClientCreatorFuncWasCalled := false
					err := getKubeConfig(outputBuffer,
						warningsBuffer,
						"some-token",
						"./testdata/kubeconfig.yaml",
						"",
						"some-namespace",
						func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
							kubeClientCreatorFuncWasCalled = true
							r.Equal("https://fake-server-url-value", restConfig.Host)
							r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
							return pinnipedClient, nil
						},
					)
					r.NoError(err)
					r.True(kubeClientCreatorFuncWasCalled)

					r.Equal(
						"WARNING: Server and certificate authority did not match between local kubeconfig and Pinniped's CredentialIssuerConfig on the cluster. Using local kubeconfig values.\n",
						warningsBuffer.String(),
					)
					r.Equal(expectedKubeconfigYAML(
						base64.StdEncoding.EncodeToString([]byte("fake-certificate-authority-data-value")),
						"https://fake-server-url-value",
						fullPathToSelf,
						"some-token",
						"https://fake-server-url-value",
						"fake-certificate-authority-data-value",
					), outputBuffer.String())
				})
			})
		})

		when("the CredentialIssuerConfig does not exist on the cluster", func() {
			it("returns an error", func() {
				kubeClientCreatorFuncWasCalled := false
				err := getKubeConfig(outputBuffer,
					warningsBuffer,
					"some-token",
					"./testdata/kubeconfig.yaml",
					"",
					"some-namespace",
					func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
						kubeClientCreatorFuncWasCalled = true
						r.Equal("https://fake-server-url-value", restConfig.Host)
						r.Equal("fake-certificate-authority-data-value", string(restConfig.CAData))
						return pinnipedClient, nil
					},
				)
				r.True(kubeClientCreatorFuncWasCalled)
				r.EqualError(err, `CredentialIssuerConfig "pinniped-config" was not found in namespace "some-namespace". Is Pinniped installed on this cluster in namespace "some-namespace"?`)
				r.Empty(warningsBuffer.String())
				r.Empty(outputBuffer.String())
			})
		})

		when("there is an error while getting the CredentialIssuerConfig from the cluster", func() {
			it("returns an error", func() {
				err := getKubeConfig(outputBuffer,
					warningsBuffer,
					"some-token",
					"./testdata/kubeconfig.yaml",
					"",
					"some-namespace",
					func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
						return nil, fmt.Errorf("some error getting CredentialIssuerConfig")
					},
				)
				r.EqualError(err, "some error getting CredentialIssuerConfig")
				r.Empty(warningsBuffer.String())
				r.Empty(outputBuffer.String())
			})
		})

	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
