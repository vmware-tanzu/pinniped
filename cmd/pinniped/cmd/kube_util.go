// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
)

// getClientsetsFunc is a function that can return clients for the Concierge and Kubernetes APIs given a
// clientConfig and the apiGroupSuffix with which the API is running.
type getClientsetsFunc func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, kubernetes.Interface, aggregatorclient.Interface, error)

// getRealClientsets returns real implementations of the Concierge and Kubernetes client interfaces.
func getRealClientsets(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, kubernetes.Interface, aggregatorclient.Interface, error) {
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := kubeclient.New(
		kubeclient.WithConfig(restConfig),
		kubeclient.WithMiddleware(groupsuffix.New(apiGroupSuffix)),
	)
	if err != nil {
		return nil, nil, nil, err
	}
	return client.PinnipedConcierge, client.Kubernetes, client.Aggregation, nil
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
