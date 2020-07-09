/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package kube contains placeholder-name utilities related to Kubernetes.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// AnonymousClientset returns a Kubernetes client that uses anonymous auth.
func AnonymousClientset(url, caBundlePath string) (*kubernetes.Clientset, error) {
	config := clientcmdapi.NewConfig()
	config.Clusters["anonymous-cluster"] = &clientcmdapi.Cluster{
		Server:               url,
		CertificateAuthority: caBundlePath,
	}
	config.Contexts["anonymous"] = &clientcmdapi.Context{
		Cluster: "anonymous-cluster",
	}
	config.CurrentContext = "anonymous"

	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("new kubernetes rest config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("new kubernetes clientset: %w", err)
	}

	return clientset, nil
}
