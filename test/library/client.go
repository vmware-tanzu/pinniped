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

	placeholdernameclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{})
	config, err := clientConfig.ClientConfig()
	require.NoError(t, err)

	return config
}

func NewClientset(t *testing.T) kubernetes.Interface {
	t.Helper()

	return kubernetes.NewForConfigOrDie(NewClientConfig(t))
}

func NewPlaceholderNameClientset(t *testing.T) placeholdernameclientset.Interface {
	t.Helper()

	return placeholdernameclientset.NewForConfigOrDie(NewClientConfig(t))
}
