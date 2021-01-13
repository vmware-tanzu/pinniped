// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	aggregatorclientscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"

	pinnipedconciergeclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
	pinnipedconciergeclientsetscheme "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/scheme"
	pinnipedsupervisorclientset "go.pinniped.dev/generated/1.20/client/supervisor/clientset/versioned"
	pinnipedsupervisorclientsetscheme "go.pinniped.dev/generated/1.20/client/supervisor/clientset/versioned/scheme"
)

type Client struct {
	Kubernetes         kubernetes.Interface
	Aggregation        aggregatorclient.Interface
	PinnipedConcierge  pinnipedconciergeclientset.Interface
	PinnipedSupervisor pinnipedsupervisorclientset.Interface

	JSONConfig, ProtoConfig *restclient.Config
}

func New(opts ...Option) (*Client, error) {
	c := &clientConfig{}

	for _, opt := range opts {
		opt(c)
	}

	// default to assuming we are running in a pod with the service account token mounted
	if c.config == nil {
		inClusterConfig, err := restclient.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
		}
		WithConfig(inClusterConfig)(c) // make sure all writes to clientConfig flow through one code path
	}

	// explicitly use json when talking to CRD APIs
	jsonKubeConfig := createJSONKubeConfig(c.config)

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(c.config)

	// Connect to the core Kubernetes API.
	k8sClient, err := kubernetes.NewForConfig(configWithWrapper(protoKubeConfig, kubescheme.Scheme, kubescheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err := aggregatorclient.NewForConfig(configWithWrapper(protoKubeConfig, aggregatorclientscheme.Scheme, aggregatorclientscheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize aggregation client: %w", err)
	}

	// Connect to the pinniped concierge API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedConciergeClient, err := pinnipedconciergeclientset.NewForConfig(configWithWrapper(jsonKubeConfig, pinnipedconciergeclientsetscheme.Scheme, pinnipedconciergeclientsetscheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	// Connect to the pinniped supervisor API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedSupervisorClient, err := pinnipedsupervisorclientset.NewForConfig(configWithWrapper(jsonKubeConfig, pinnipedsupervisorclientsetscheme.Scheme, pinnipedsupervisorclientsetscheme.Codecs, c.middlewares))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	return &Client{
		Kubernetes:         k8sClient,
		Aggregation:        aggregatorClient,
		PinnipedConcierge:  pinnipedConciergeClient,
		PinnipedSupervisor: pinnipedSupervisorClient,

		JSONConfig:  jsonKubeConfig,
		ProtoConfig: protoKubeConfig,
	}, nil
}

// Returns a copy of the input config with the ContentConfig set to use json.
// Use this config to communicate with all CRD based APIs.
func createJSONKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	jsonKubeConfig := restclient.CopyConfig(kubeConfig)
	jsonKubeConfig.AcceptContentTypes = runtime.ContentTypeJSON
	jsonKubeConfig.ContentType = runtime.ContentTypeJSON
	return jsonKubeConfig
}

// Returns a copy of the input config with the ContentConfig set to use protobuf.
// Do not use this config to communicate with any CRD based APIs.
func createProtoKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	protoKubeConfig := restclient.CopyConfig(kubeConfig)
	const protoThenJSON = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	protoKubeConfig.AcceptContentTypes = protoThenJSON
	protoKubeConfig.ContentType = runtime.ContentTypeProtobuf
	return protoKubeConfig
}
