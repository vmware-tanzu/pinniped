/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	placeholdernameclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()

	return newClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{})
}

func NewClientConfigWithCertAndKey(t *testing.T, cert, key string) *rest.Config {
	t.Helper()

	return newClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{
		AuthInfo: clientcmdapi.AuthInfo{
			ClientCertificateData: []byte(base64.StdEncoding.EncodeToString([]byte(cert))),
			ClientKeyData:         []byte(base64.StdEncoding.EncodeToString([]byte(key))),
		},
	})
}

func newClientConfigWithOverrides(t *testing.T, overrides *clientcmd.ConfigOverrides) *rest.Config {
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

func NewClientsetWithConfig(t *testing.T, config *rest.Config) kubernetes.Interface {
	t.Helper()

	return kubernetes.NewForConfigOrDie(config)
}

func NewPlaceholderNameClientset(t *testing.T) placeholdernameclientset.Interface {
	t.Helper()

	return placeholdernameclientset.NewForConfigOrDie(NewClientConfig(t))
}
