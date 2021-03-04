// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"k8s.io/client-go/tools/clientcmd"

	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
)

// getConciergeClientsetFunc is a function that can return a clientset for the Concierge API given a
// clientConfig and the apiGroupSuffix with which the API is running.
type getConciergeClientsetFunc func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error)

// getRealConciergeClientset returns a real implementation of a conciergeclientset.Interface.
func getRealConciergeClientset(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error) {
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubeclient.New(
		kubeclient.WithConfig(restConfig),
		kubeclient.WithMiddleware(groupsuffix.New(apiGroupSuffix)),
	)
	if err != nil {
		return nil, err
	}
	return client.PinnipedConcierge, nil
}

// newClientConfig returns a clientcmd.ClientConfig given an optional kubeconfig path override and
// an optional context override.
func newClientConfig(kubeconfigPathOverride string, currentContextName string) clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPathOverride
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{
		CurrentContext: currentContextName,
	})
	return clientConfig
}
