/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	pinnipedclientset "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned"

	// Import to initialize client auth plugins - the kubeconfig that we use for
	// testing may use gcloud, az, oidc, etc.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()

	return newClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{})
}

func NewClientset(t *testing.T) kubernetes.Interface {
	t.Helper()

	return newClientsetWithConfig(t, NewClientConfig(t))
}

func NewClientsetWithCertAndKey(t *testing.T, clientCertificateData, clientKeyData string) kubernetes.Interface {
	t.Helper()

	return newClientsetWithConfig(t, newAnonymousClientRestConfigWithCertAndKeyAdded(t, clientCertificateData, clientKeyData))
}

func NewPinnipedClientset(t *testing.T) pinnipedclientset.Interface {
	t.Helper()

	return pinnipedclientset.NewForConfigOrDie(NewClientConfig(t))
}

func NewAnonymousPinnipedClientset(t *testing.T) pinnipedclientset.Interface {
	t.Helper()

	return pinnipedclientset.NewForConfigOrDie(newAnonymousClientRestConfig(t))
}

func NewAggregatedClientset(t *testing.T) aggregatorclient.Interface {
	t.Helper()

	return aggregatorclient.NewForConfigOrDie(NewClientConfig(t))
}

func newClientConfigWithOverrides(t *testing.T, overrides *clientcmd.ConfigOverrides) *rest.Config {
	t.Helper()

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)
	config, err := clientConfig.ClientConfig()
	require.NoError(t, err)
	return config
}

func newClientsetWithConfig(t *testing.T, config *rest.Config) kubernetes.Interface {
	t.Helper()

	result, err := kubernetes.NewForConfig(config)
	require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")
	return result
}

// Returns a rest.Config without any user authentication info.
// Ensures that we are not accidentally picking up any authentication info from the kube config file.
// E.g. If your kube config were pointing at an Azure cluster, it would have both certs and a token,
// and we don't want our tests to accidentally pick up that token.
func newAnonymousClientRestConfig(t *testing.T) *rest.Config {
	t.Helper()

	realConfig := NewClientConfig(t)

	out, err := ioutil.TempFile("", "pinniped-anonymous-kubeconfig-test-*")
	require.NoError(t, err)
	defer os.Remove(out.Name())

	anonConfig := clientcmdapi.NewConfig()
	anonConfig.Clusters["anonymous-cluster"] = &clientcmdapi.Cluster{
		Server:                   realConfig.Host,
		CertificateAuthorityData: realConfig.CAData,
	}
	anonConfig.Contexts["anonymous"] = &clientcmdapi.Context{
		Cluster: "anonymous-cluster",
	}
	anonConfig.CurrentContext = "anonymous"

	data, err := clientcmd.Write(*anonConfig)
	require.NoError(t, err)

	_, err = out.Write(data)
	require.NoError(t, err)

	restConfig, err := clientcmd.BuildConfigFromFlags("", out.Name())
	require.NoError(t, err)

	return restConfig
}

// Starting with an anonymous client config, add a cert and key to use for authentication in the API server.
func newAnonymousClientRestConfigWithCertAndKeyAdded(t *testing.T, clientCertificateData, clientKeyData string) *rest.Config {
	t.Helper()

	config := newAnonymousClientRestConfig(t)
	config.CertData = []byte(clientCertificateData)
	config.KeyData = []byte(clientKeyData)
	return config
}
