/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controllermanager

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/suzerain-io/controller-go"
	"github.com/suzerain-io/placeholder-name/internal/controller/apicerts"
	"github.com/suzerain-io/placeholder-name/internal/controller/logindiscovery"
	"github.com/suzerain-io/placeholder-name/internal/provider"
	placeholderclientset "github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go/clientset/versioned"
	placeholderinformers "github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go/informers/externalversions"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

// Prepare the controllers and their informers and return a function that will start them when called.
func PrepareControllers(
	serverInstallationNamespace string,
	discoveryURLOverride *string,
	dynamicCertProvider provider.DynamicTLSServingCertProvider,
) (func(ctx context.Context), error) {
	// Create k8s clients.
	k8sClient, aggregatorClient, placeholderClient, err := createClients()
	if err != nil {
		return nil, fmt.Errorf("could not create clients for the controllers: %w", err)
	}

	// Create informers. Don't forget to make sure they get started in the function returned below.
	kubePublicNamespaceK8sInformers, installationNamespaceK8sInformers, installationNamespacePlaceholderInformers :=
		createInformers(serverInstallationNamespace, k8sClient, placeholderClient)

	// Create controller manager.
	controllerManager := controller.
		NewManager().
		WithController(
			logindiscovery.NewPublisherController(
				serverInstallationNamespace,
				discoveryURLOverride,
				placeholderClient,
				kubePublicNamespaceK8sInformers.Core().V1().ConfigMaps(),
				installationNamespacePlaceholderInformers.Crds().V1alpha1().LoginDiscoveryConfigs(),
				controller.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsManagerController(
				serverInstallationNamespace,
				k8sClient,
				aggregatorClient,
				installationNamespaceK8sInformers.Core().V1().Secrets(),
				controller.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				serverInstallationNamespace,
				dynamicCertProvider,
				installationNamespaceK8sInformers.Core().V1().Secrets(),
				controller.WithInformer,
			),
			singletonWorker,
		)

	// Return a function which starts the informers and controllers.
	return func(ctx context.Context) {
		kubePublicNamespaceK8sInformers.Start(ctx.Done())
		installationNamespaceK8sInformers.Start(ctx.Done())
		installationNamespacePlaceholderInformers.Start(ctx.Done())

		go controllerManager.Start(ctx)
	}, nil
}

// Create the k8s clients that will be used by the controllers.
func createClients() (
	k8sClient *kubernetes.Clientset,
	aggregatorClient *aggregatorclient.Clientset,
	placeholderClient *placeholderclientset.Clientset,
	err error,
) {
	// Load the Kubernetes client configuration (kubeconfig),
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(kubeConfig)

	// Connect to the core Kubernetes API.
	k8sClient, err = kubernetes.NewForConfig(protoKubeConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err = aggregatorclient.NewForConfig(protoKubeConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the placeholder API.
	// I think we can't use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not supported).
	placeholderClient, err = placeholderclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize placeholder client: %w", err)
	}

	//nolint: nakedret
	return
}

// Create the informers that will be used by the controllers.
func createInformers(
	serverInstallationNamespace string,
	k8sClient *kubernetes.Clientset,
	placeholderClient *placeholderclientset.Clientset,
) (
	kubePublicNamespaceK8sInformers k8sinformers.SharedInformerFactory,
	installationNamespaceK8sInformers k8sinformers.SharedInformerFactory,
	installationNamespacePlaceholderInformers placeholderinformers.SharedInformerFactory,
) {
	kubePublicNamespaceK8sInformers = k8sinformers.NewSharedInformerFactoryWithOptions(
		k8sClient,
		defaultResyncInterval,
		k8sinformers.WithNamespace(logindiscovery.ClusterInfoNamespace),
	)
	installationNamespaceK8sInformers = k8sinformers.NewSharedInformerFactoryWithOptions(
		k8sClient,
		defaultResyncInterval,
		k8sinformers.WithNamespace(serverInstallationNamespace),
	)
	installationNamespacePlaceholderInformers = placeholderinformers.NewSharedInformerFactoryWithOptions(
		placeholderClient,
		defaultResyncInterval,
		placeholderinformers.WithNamespace(serverInstallationNamespace),
	)
	return
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
