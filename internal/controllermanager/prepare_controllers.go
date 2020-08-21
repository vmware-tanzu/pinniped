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
	"github.com/suzerain-io/pinniped/internal/controller/apicerts"
	"github.com/suzerain-io/pinniped/internal/controller/issuerconfig"
	"github.com/suzerain-io/pinniped/internal/provider"
	pinnipedclientset "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/clientset/versioned"
	pinnipedinformers "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/informers/externalversions"
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
	servingCertDuration time.Duration,
	servingCertRenewBefore time.Duration,
) (func(ctx context.Context), error) {
	// Create k8s clients.
	k8sClient, aggregatorClient, pinnipedClient, err := createClients()
	if err != nil {
		return nil, fmt.Errorf("could not create clients for the controllers: %w", err)
	}

	// Create informers. Don't forget to make sure they get started in the function returned below.
	kubePublicNamespaceK8sInformers, installationNamespaceK8sInformers, installationNamespacePinnipedInformers :=
		createInformers(serverInstallationNamespace, k8sClient, pinnipedClient)

	// Create controller manager.
	controllerManager := controller.
		NewManager().
		WithController(
			issuerconfig.NewPublisherController(
				serverInstallationNamespace,
				discoveryURLOverride,
				pinnipedClient,
				kubePublicNamespaceK8sInformers.Core().V1().ConfigMaps(),
				installationNamespacePinnipedInformers.Crd().V1alpha1().CredentialIssuerConfigs(),
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
				controller.WithInitialEvent,
				servingCertDuration,
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
		).
		WithController(
			apicerts.NewCertsExpirerController(
				serverInstallationNamespace,
				k8sClient,
				installationNamespaceK8sInformers.Core().V1().Secrets(),
				controller.WithInformer,
				servingCertRenewBefore,
			),
			singletonWorker,
		)

	// Return a function which starts the informers and controllers.
	return func(ctx context.Context) {
		kubePublicNamespaceK8sInformers.Start(ctx.Done())
		installationNamespaceK8sInformers.Start(ctx.Done())
		installationNamespacePinnipedInformers.Start(ctx.Done())

		go controllerManager.Start(ctx)
	}, nil
}

// Create the k8s clients that will be used by the controllers.
func createClients() (
	k8sClient *kubernetes.Clientset,
	aggregatorClient *aggregatorclient.Clientset,
	pinnipedClient *pinnipedclientset.Clientset,
	err error,
) {
	// Load the Kubernetes client configuration.
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

	// Connect to the pinniped API.
	// I think we can't use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not supported).
	pinnipedClient, err = pinnipedclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	//nolint: nakedret
	return
}

// Create the informers that will be used by the controllers.
func createInformers(
	serverInstallationNamespace string,
	k8sClient *kubernetes.Clientset,
	pinnipedClient *pinnipedclientset.Clientset,
) (
	kubePublicNamespaceK8sInformers k8sinformers.SharedInformerFactory,
	installationNamespaceK8sInformers k8sinformers.SharedInformerFactory,
	installationNamespacePinnipedInformers pinnipedinformers.SharedInformerFactory,
) {
	kubePublicNamespaceK8sInformers = k8sinformers.NewSharedInformerFactoryWithOptions(
		k8sClient,
		defaultResyncInterval,
		k8sinformers.WithNamespace(issuerconfig.ClusterInfoNamespace),
	)
	installationNamespaceK8sInformers = k8sinformers.NewSharedInformerFactoryWithOptions(
		k8sClient,
		defaultResyncInterval,
		k8sinformers.WithNamespace(serverInstallationNamespace),
	)
	installationNamespacePinnipedInformers = pinnipedinformers.NewSharedInformerFactoryWithOptions(
		pinnipedClient,
		defaultResyncInterval,
		pinnipedinformers.WithNamespace(serverInstallationNamespace),
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
