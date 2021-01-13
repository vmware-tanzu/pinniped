// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package controllermanager provides an entrypoint into running all of the controllers that run as
// a part of Pinniped.
package controllermanager

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2/klogr"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/1.20/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/authenticator/cachecleaner"
	"go.pinniped.dev/internal/controller/authenticator/jwtcachefiller"
	"go.pinniped.dev/internal/controller/authenticator/webhookcachefiller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controller/kubecertagent"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/deploymentref"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

// Config holds all the input parameters to the set of controllers run as a part of Pinniped.
//
// It is used to inject parameters into PrepareControllers.
type Config struct {
	// ServerInstallationInfo provides the name of the pod in which Pinniped is running and the namespace in which Pinniped is deployed.
	ServerInstallationInfo *downward.PodInfo

	// APIGroupSuffix is the suffix of the Pinniped API that should be targeted by these controllers.
	APIGroupSuffix string

	// NamesConfig comes from the Pinniped config API (see api.Config). It specifies how Kubernetes
	// objects should be named.
	NamesConfig *concierge.NamesConfigSpec

	// KubeCertAgentConfig comes from the Pinniped config API (see api.Config). It configures how
	// the kubecertagent package's controllers should manage the agent pods.
	KubeCertAgentConfig *concierge.KubeCertAgentSpec

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

	// AuthenticatorCache is a cache of authenticators shared amongst various authenticated-related controllers.
	AuthenticatorCache *authncache.Cache

	// Labels are labels that should be added to any resources created by the controllers.
	Labels map[string]string
}

// Prepare the controllers and their informers and return a function that will start them when called.
//nolint:funlen // Eh, fair, it is a really long function...but it is wiring the world...so...
func PrepareControllers(c *Config) (func(ctx context.Context), error) {
	dref, _, err := deploymentref.New(c.ServerInstallationInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot create deployment ref: %w", err)
	}

	client, err := kubeclient.New(
		dref,
		kubeclient.WithMiddleware(groupsuffix.New(c.APIGroupSuffix)),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create clients for the controllers: %w", err)
	}

	// Create informers. Don't forget to make sure they get started in the function returned below.
	informers := createInformers(c.ServerInstallationInfo.Namespace, client.Kubernetes, client.PinnipedConcierge)

	// Configuration for the kubecertagent controllers created below.
	agentPodConfig := &kubecertagent.AgentPodConfig{
		Namespace:                 c.ServerInstallationInfo.Namespace,
		ContainerImage:            *c.KubeCertAgentConfig.Image,
		PodNamePrefix:             *c.KubeCertAgentConfig.NamePrefix,
		ContainerImagePullSecrets: c.KubeCertAgentConfig.ImagePullSecrets,
		AdditionalLabels:          c.Labels,
	}
	credentialIssuerLocationConfig := &kubecertagent.CredentialIssuerLocationConfig{
		Namespace: c.ServerInstallationInfo.Namespace,
		Name:      c.NamesConfig.CredentialIssuer,
	}

	groupName, ok := groupsuffix.Replace(loginv1alpha1.GroupName, c.APIGroupSuffix)
	if !ok {
		return nil, fmt.Errorf("cannot make api group from %s/%s", loginv1alpha1.GroupName, c.APIGroupSuffix)
	}
	apiServiceName := loginv1alpha1.SchemeGroupVersion.Version + "." + groupName

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().

		// KubeConfig info publishing controller is responsible for writing the KubeConfig information to the
		// CredentialIssuer resource and keeping that information up to date.
		WithController(
			issuerconfig.NewKubeConfigInfoPublisherController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.CredentialIssuer,
				c.Labels,
				c.DiscoveryURLOverride,
				client.PinnipedConcierge,
				informers.kubePublicNamespaceK8s.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).

		// API certs controllers are responsible for managing the TLS certificates used to serve Pinniped's API.
		WithController(
			apicerts.NewCertsManagerController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				c.Labels,
				client.Kubernetes,
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
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				apiServiceName,
				client.Aggregation,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				c.DynamicServingCertProvider,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsExpirerController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				c.ServingCertRenewBefore,
			),
			singletonWorker,
		).

		// Kube cert agent controllers are responsible for finding the cluster's signing keys and keeping them
		// up to date in memory, as well as reporting status on this cluster integration strategy.
		WithController(
			kubecertagent.NewCreaterController(
				agentPodConfig,
				credentialIssuerLocationConfig,
				c.Labels,
				clock.RealClock{},
				client.Kubernetes,
				client.PinnipedConcierge,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewAnnotaterController(
				agentPodConfig,
				credentialIssuerLocationConfig,
				clock.RealClock{},
				client.Kubernetes,
				client.PinnipedConcierge,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewExecerController(
				credentialIssuerLocationConfig,
				c.DynamicSigningCertProvider,
				kubecertagent.NewPodCommandExecutor(client.JSONConfig, client.Kubernetes),
				client.PinnipedConcierge,
				clock.RealClock{},
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			kubecertagent.NewDeleterController(
				agentPodConfig,
				client.Kubernetes,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).

		// The cache filler/cleaner controllers are responsible for keep an in-memory representation of active
		// authenticators up to date.
		WithController(
			webhookcachefiller.New(
				c.AuthenticatorCache,
				informers.installationNamespacePinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			jwtcachefiller.New(
				c.AuthenticatorCache,
				informers.installationNamespacePinniped.Authentication().V1alpha1().JWTAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			cachecleaner.New(
				c.AuthenticatorCache,
				informers.installationNamespacePinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				informers.installationNamespacePinniped.Authentication().V1alpha1().JWTAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		)

	// Return a function which starts the informers and controllers.
	return func(ctx context.Context) {
		informers.startAndWaitForSync(ctx)
		go controllerManager.Start(ctx)
	}, nil
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
	k8sClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
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
