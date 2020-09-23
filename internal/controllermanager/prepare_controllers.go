// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package controllermanager provides an entrypoint into running all of the controllers that run as
// a part of Pinniped.
package controllermanager

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2/klogr"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	loginv1alpha1 "go.pinniped.dev/generated/1.19/apis/login/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controller/identityprovider/idpcache"
	"go.pinniped.dev/internal/controller/identityprovider/webhookcachecleaner"
	"go.pinniped.dev/internal/controller/identityprovider/webhookcachefiller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controller/kubecertagent"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/pkg/config/api"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

// Config holds all the input parameters to the set of controllers run as a part of Pinniped.
//
// It is used to inject parameters into PrepareControllers.
type Config struct {
	// ServerInstallationNamespace provides the namespace in which Pinniped is deployed.
	ServerInstallationNamespace string

	// NamesConfig comes from the Pinniped config API (see api.Config). It specifies how Kubernetes
	// objects should be named.
	NamesConfig *api.NamesConfigSpec

	// DiscoveryURLOverride allows a caller to inject a hardcoded discovery URL into Pinniped
	// discovery document.
	DiscoveryURLOverride *string

	// DynamicServingCertProvider provides a setter and a getter to the Pinniped API's serving cert.
	DynamicServingCertProvider dynamiccert.Provider
	// DynamicSigningCertProvider provides a setter and a getter to the Pinniped API's
	// signing cert, i.e., the cert that it uses to sign certs for Pinniped clients wishing to login.
	DynamicSigningCertProvider dynamiccert.Provider

	// ServingCertDuration is the validity period, in seconds, of the API serving certificate.
	ServingCertDuration time.Duration
	// ServingCertRenewBefore is the period of time, in seconds, that pinniped will wait before
	// rotating the serving certificate. This period of time starts upon issuance of the serving
	// certificate.
	ServingCertRenewBefore time.Duration

	// IDPCache is a cache of authenticators shared amongst various IDP-related controllers.
	IDPCache *idpcache.Cache

	// KubeCertAgentTemplate is the template from which the kube-cert-agent controllers will create a
	// kube-cert-agent pod. See kubecertagent.Info for more details.
	KubeCertAgentTemplate *corev1.Pod
	// KubeCertAgentCertPathAnnotation is the name of the annotation key that will be used when
	// setting the best-guess path to the kube API's certificate. See kubecertagent.Info for more
	// details.
	KubeCertAgentCertPathAnnotation string
	// KubeCertAgentKeyPathAnnotation is the name of the annotation key that will be used when setting
	// the best-guess path to the kube API's key. See kubecertagent.Info for more details.
	KubeCertAgentKeyPathAnnotation string
}

// Prepare the controllers and their informers and return a function that will start them when called.
//nolint:funlen // Eh, fair, it is a really long function...but it is wiring the world...so...
func PrepareControllers(c *Config) (func(ctx context.Context), error) {
	// Create k8s clients.
	kubeConfig, err := createConfig()
	if err != nil {
		return nil, fmt.Errorf("could not create config for the controllers: %w", err)
	}
	k8sClient, aggregatorClient, pinnipedClient, err := createClients(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create clients for the controllers: %w", err)
	}

	// Create informers. Don't forget to make sure they get started in the function returned below.
	informers := createInformers(c.ServerInstallationNamespace, k8sClient, pinnipedClient)

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			issuerconfig.NewKubeConfigInfoPublisherController(
				c.ServerInstallationNamespace,
				c.NamesConfig.CredentialIssuerConfig,
				c.DiscoveryURLOverride,
				pinnipedClient,
				informers.kubePublicNamespaceK8s.Core().V1().ConfigMaps(),
				informers.installationNamespacePinniped.Config().V1alpha1().CredentialIssuerConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsManagerController(
				c.ServerInstallationNamespace,
				c.NamesConfig.ServingCertificateSecret,
				k8sClient,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				c.ServingCertDuration,
				"Pinniped CA",
				c.NamesConfig.APIService,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewAPIServiceUpdaterController(
				c.ServerInstallationNamespace,
				c.NamesConfig.ServingCertificateSecret,
				loginv1alpha1.SchemeGroupVersion.Version+"."+loginv1alpha1.GroupName,
				aggregatorClient,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				c.ServerInstallationNamespace,
				c.NamesConfig.ServingCertificateSecret,
				c.DynamicServingCertProvider,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsExpirerController(
				c.ServerInstallationNamespace,
				c.NamesConfig.ServingCertificateSecret,
				k8sClient,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				c.ServingCertRenewBefore,
			),
			singletonWorker,
		).
		WithController(
			webhookcachefiller.New(
				c.IDPCache,
				informers.installationNamespacePinniped.IDP().V1alpha1().WebhookIdentityProviders(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			webhookcachecleaner.New(
				c.IDPCache,
				informers.installationNamespacePinniped.IDP().V1alpha1().WebhookIdentityProviders(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewCreaterController(
				&kubecertagent.Info{
					Template: c.KubeCertAgentTemplate,
				},
				k8sClient,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewDeleterController(
				&kubecertagent.Info{
					Template: c.KubeCertAgentTemplate,
				},
				k8sClient,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewAnnotaterController(
				&kubecertagent.Info{
					Template:           c.KubeCertAgentTemplate,
					CertPathAnnotation: c.KubeCertAgentCertPathAnnotation,
					KeyPathAnnotation:  c.KubeCertAgentKeyPathAnnotation,
				},
				k8sClient,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewExecerController(
				&kubecertagent.Info{
					Template:           c.KubeCertAgentTemplate,
					CertPathAnnotation: c.KubeCertAgentCertPathAnnotation,
					KeyPathAnnotation:  c.KubeCertAgentKeyPathAnnotation,
				},
				c.ServerInstallationNamespace,
				c.NamesConfig.CredentialIssuerConfig,
				c.DynamicSigningCertProvider,
				kubecertagent.NewPodCommandExecutor(kubeConfig, k8sClient),
				pinnipedClient,
				clock.RealClock{},
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	// Return a function which starts the informers and controllers.
	return func(ctx context.Context) {
		informers.startAndWaitForSync(ctx)
		go controllerManager.Start(ctx)
	}, nil
}

// Create the rest config that will be used by the clients for the controllers.
func createConfig() (*rest.Config, error) {
	// Load the Kubernetes client configuration.
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	return kubeConfig, nil
}

// Create the k8s clients that will be used by the controllers.
func createClients(kubeConfig *rest.Config) (
	k8sClient *kubernetes.Clientset,
	aggregatorClient *aggregatorclient.Clientset,
	pinnipedClient *pinnipedclientset.Clientset,
	err error,
) {
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

	//nolint: nakedret // Short function. Makes the order of return values more clear.
	return
}

type informers struct {
	kubePublicNamespaceK8s        k8sinformers.SharedInformerFactory
	kubeSystemNamespaceK8s        k8sinformers.SharedInformerFactory
	installationNamespaceK8s      k8sinformers.SharedInformerFactory
	installationNamespacePinniped pinnipedinformers.SharedInformerFactory
}

// Create the informers that will be used by the controllers.
func createInformers(
	serverInstallationNamespace string,
	k8sClient *kubernetes.Clientset,
	pinnipedClient *pinnipedclientset.Clientset,
) *informers {
	return &informers{
		kubePublicNamespaceK8s: k8sinformers.NewSharedInformerFactoryWithOptions(
			k8sClient,
			defaultResyncInterval,
			k8sinformers.WithNamespace(issuerconfig.ClusterInfoNamespace),
		),
		kubeSystemNamespaceK8s: k8sinformers.NewSharedInformerFactoryWithOptions(
			k8sClient,
			defaultResyncInterval,
			k8sinformers.WithNamespace(kubecertagent.ControllerManagerNamespace),
		),
		installationNamespaceK8s: k8sinformers.NewSharedInformerFactoryWithOptions(
			k8sClient,
			defaultResyncInterval,
			k8sinformers.WithNamespace(serverInstallationNamespace),
		),
		installationNamespacePinniped: pinnipedinformers.NewSharedInformerFactoryWithOptions(
			pinnipedClient,
			defaultResyncInterval,
			pinnipedinformers.WithNamespace(serverInstallationNamespace),
		),
	}
}

func (i *informers) startAndWaitForSync(ctx context.Context) {
	i.kubePublicNamespaceK8s.Start(ctx.Done())
	i.kubeSystemNamespaceK8s.Start(ctx.Done())
	i.installationNamespaceK8s.Start(ctx.Done())
	i.installationNamespacePinniped.Start(ctx.Done())

	i.kubePublicNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.kubeSystemNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.installationNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.installationNamespacePinniped.WaitForCacheSync(ctx.Done())
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
