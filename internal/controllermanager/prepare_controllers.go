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

	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/apiserviceref"
	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/authenticator/cachecleaner"
	"go.pinniped.dev/internal/controller/authenticator/jwtcachefiller"
	"go.pinniped.dev/internal/controller/authenticator/webhookcachefiller"
	"go.pinniped.dev/internal/controller/impersonatorconfig"
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
	// DynamicSigningCertProvider provides a setter and a getter to the Pinniped API's  // TODO fix comment
	// signing cert, i.e., the cert that it uses to sign certs for Pinniped clients wishing to login.
	DynamicSigningCertProvider dynamiccert.Provider
	// TODO fix comment
	ImpersonationSigningCertProvider dynamiccert.Provider

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
	loginConciergeGroupData, identityConciergeGroupData := groupsuffix.ConciergeAggregatedGroups(c.APIGroupSuffix)

	dref, _, err := deploymentref.New(c.ServerInstallationInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot create deployment ref: %w", err)
	}

	apiServiceRef, err := apiserviceref.New(loginConciergeGroupData.APIServiceName())
	if err != nil {
		return nil, fmt.Errorf("cannot create API service ref: %w", err)
	}

	client, err := kubeclient.New(
		dref,          // first try to use the deployment as an owner ref (for namespace scoped resources)
		apiServiceRef, // fallback to our API service (for everything else we create)
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
		Name: c.NamesConfig.CredentialIssuer,
	}

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().

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
				loginConciergeGroupData.APIServiceName(),
				client.Aggregation,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewAPIServiceUpdaterController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				identityConciergeGroupData.APIServiceName(),
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
				apicerts.TLSCertificateChainSecretKey,
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
				c.Labels,
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
				c.Labels,
				c.DiscoveryURLOverride,
				c.DynamicSigningCertProvider,
				kubecertagent.NewPodCommandExecutor(client.JSONConfig, client.Kubernetes),
				client.PinnipedConcierge,
				clock.RealClock{},
				informers.installationNamespaceK8s.Core().V1().Pods(),
				informers.kubePublicNamespaceK8s.Core().V1().ConfigMaps(),
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
				informers.pinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			jwtcachefiller.New(
				c.AuthenticatorCache,
				informers.pinniped.Authentication().V1alpha1().JWTAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		).
		WithController(
			cachecleaner.New(
				c.AuthenticatorCache,
				informers.pinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				informers.pinniped.Authentication().V1alpha1().JWTAuthenticators(),
				klogr.New(),
			),
			singletonWorker,
		).

		// The impersonator configuration controller dynamically configures the impersonation proxy feature.
		WithController(
			impersonatorconfig.NewImpersonatorConfigController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ImpersonationConfigMap,
				c.NamesConfig.CredentialIssuer,
				client.Kubernetes,
				client.PinnipedConcierge,
				informers.installationNamespaceK8s.Core().V1().ConfigMaps(),
				informers.installationNamespaceK8s.Core().V1().Services(),
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				c.NamesConfig.ImpersonationLoadBalancerService,
				c.NamesConfig.ImpersonationTLSCertificateSecret,
				c.NamesConfig.ImpersonationCACertificateSecret,
				c.Labels,
				clock.RealClock{},
				impersonator.New,
				c.NamesConfig.ImpersonationSignerSecret,
				c.ImpersonationSigningCertProvider,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsManagerController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ImpersonationSignerSecret,
				c.Labels,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				365*24*time.Hour, // 1 year hard coded value
				"Pinniped Impersonation Proxy CA",
				"", // optional, means do not give me a serving cert
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsExpirerController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ImpersonationSignerSecret,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				c.ServingCertRenewBefore,
				apicerts.CACertificateSecretKey,
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
	kubePublicNamespaceK8s   k8sinformers.SharedInformerFactory
	kubeSystemNamespaceK8s   k8sinformers.SharedInformerFactory
	installationNamespaceK8s k8sinformers.SharedInformerFactory
	pinniped                 pinnipedinformers.SharedInformerFactory
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
			k8sinformers.WithNamespace(kubecertagent.ClusterInfoNamespace),
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
		pinniped: pinnipedinformers.NewSharedInformerFactoryWithOptions(
			pinnipedClient,
			defaultResyncInterval,
		),
	}
}

func (i *informers) startAndWaitForSync(ctx context.Context) {
	i.kubePublicNamespaceK8s.Start(ctx.Done())
	i.kubeSystemNamespaceK8s.Start(ctx.Done())
	i.installationNamespaceK8s.Start(ctx.Done())
	i.pinniped.Start(ctx.Done())

	i.kubePublicNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.kubeSystemNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.installationNamespaceK8s.WaitForCacheSync(ctx.Done())
	i.pinniped.WaitForCacheSync(ctx.Done())
}
