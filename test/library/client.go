/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()
	return NewClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{})
}

func NewClientConfigWithCertificate(t *testing.T, cert, key []byte) *rest.Config {
	t.Helper()
	return NewClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{
		AuthInfo: clientcmd.AuthInfo{
			ClientCertificateData: cert,
			ClientKeyData:         key,
		},
	})
}

func NewClientConfigWithOverrides(t *testing.T, overrides *clientcmd.ConfigOverrides) *rest.Config {
	t.Helper()

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)
	config, err := clientConfig.ClientConfig()
	require.NoError(t, err)

	return config
}

func NewClientset(t *testing.T) kubernetes.Interface {
	t.Helper()
	return NewClientsetWithConfig(t, NewClientConfig(t))
}

func NewClientsetWithConfig(t *testing.T, config *rest.Config) {
	t.Helper()
	return kubernetes.NewForConfigOrDie(config)
}

func NewPlaceholderClientset(t *testing.T) placeholderv1alpha1.PlaceholderV1alpha1Interface {
	t.Helper()

	return placeholderv1alpha1.NewForConfigOrDie(NewClientConfig(t))
}
