// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"time"

	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
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
	"go.pinniped.dev/internal/controller/serviceaccounttokencleanup"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/deploymentref"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/leaderelection"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/proxydetect"
	"go.pinniped.dev/internal/tokenclient"
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

	// ImpersonationProxyServerPort decides which port the impersonation proxy should bind.
	ImpersonationProxyServerPort int

	// DiscoveryURLOverride allows a caller to inject a hardcoded discovery URL into Pinniped
	// discovery document.
	DiscoveryURLOverride *string

	// DynamicServingCertProvider provides a setter and a getter to the Pinniped API's serving cert.
	DynamicServingCertProvider dynamiccert.Private

	// DynamicSigningCertProvider provides a setter and a getter to the Pinniped API's
	// signing cert, i.e., the cert that it uses to sign certs for Pinniped clients wishing to login.
	// This is filled with the Kube API server's signing cert by a controller, if it can be found.
	DynamicSigningCertProvider dynamiccert.Private

	// ImpersonationSigningCertProvider provides a setter and a getter to the CA cert that should be
	// used to sign client certs for authentication to the impersonation proxy. This CA is used by
	// the TokenCredentialRequest to sign certs and by the impersonation proxy to check certs.
	// When the impersonation proxy is not running, the getter will return nil cert and nil key.
	// (Note that the impersonation proxy also accepts client certs signed by the Kube API server's cert.)
	ImpersonationSigningCertProvider dynamiccert.Provider

	// ImpersonationProxyTokenCache holds short-lived tokens for the impersonation proxy service account.
	ImpersonationProxyTokenCache tokenclient.ExpiringSingletonTokenCacheGet

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

// PrepareControllers prepares the controllers and their informers and returns a function that will start them when called.
func PrepareControllers(c *Config) (controllerinit.RunnerBuilder, error) { //nolint:funlen // Eh, fair, it is a really long function...but it is wiring the world...so...
	loginConciergeGroupData, identityConciergeGroupData := groupsuffix.ConciergeAggregatedGroups(c.APIGroupSuffix)

	dref, deployment, _, err := deploymentref.New(c.ServerInstallationInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot create deployment ref: %w", err)
	}

	apiServiceRef, err := apiserviceref.New(loginConciergeGroupData.APIServiceName())
	if err != nil {
		return nil, fmt.Errorf("cannot create API service ref: %w", err)
	}

	client, leaderElector, err := leaderelection.New(
		c.ServerInstallationInfo,
		deployment,
		dref,          // first try to use the deployment as an owner ref (for namespace scoped resources)
		apiServiceRef, // fallback to our API service (for everything else we create)
		kubeclient.WithMiddleware(groupsuffix.New(c.APIGroupSuffix)),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create clients for the controllers: %w", err)
	}

	// Create informers. Don't forget to make sure they get started in the function returned below.
	informers := createInformers(c.ServerInstallationInfo.Namespace, client.Kubernetes, client.PinnipedConcierge)

	agentConfig := kubecertagent.AgentConfig{
		Namespace:                 c.ServerInstallationInfo.Namespace,
		ServiceAccountName:        c.NamesConfig.AgentServiceAccount,
		ContainerImage:            *c.KubeCertAgentConfig.Image,
		NamePrefix:                *c.KubeCertAgentConfig.NamePrefix,
		ContainerImagePullSecrets: c.KubeCertAgentConfig.ImagePullSecrets,
		Labels:                    c.Labels,
		CredentialIssuerName:      c.NamesConfig.CredentialIssuer,
		DiscoveryURLOverride:      c.DiscoveryURLOverride,
	}

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().

		// API certs controllers are responsible for managing the TLS certificates used to serve Pinniped's API.
		WithController(
			apicerts.NewCertsCreatorController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ServingCertificateSecret,
				c.Labels,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				c.ServingCertDuration,
				"Pinniped Aggregation CA",
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
				plog.New(),
			),
			singletonWorker,
		).
		// The kube-cert-agent controller is responsible for finding the cluster's signing keys and keeping them
		// up to date in memory, as well as reporting status on this cluster integration strategy.
		WithController(
			kubecertagent.NewAgentController(
				agentConfig,
				client,
				informers.kubeSystemNamespaceK8s.Core().V1().Pods(),
				informers.installationNamespaceK8s.Apps().V1().Deployments(),
				informers.installationNamespaceK8s.Core().V1().Pods(),
				informers.kubePublicNamespaceK8s.Core().V1().ConfigMaps(),
				informers.pinniped.Config().V1alpha1().CredentialIssuers(),
				c.DynamicSigningCertProvider,
			),
			singletonWorker,
		).
		// The kube-cert-agent legacy pod cleaner controller is responsible for cleaning up pods that were deployed by
		// versions of Pinniped prior to v0.7.0. If we stop supporting upgrades from v0.7.0, we can safely remove this.
		WithController(
			kubecertagent.NewLegacyPodCleanerController(
				agentConfig,
				client,
				informers.installationNamespaceK8s.Core().V1().Pods(),
				plog.New(),
			),
			singletonWorker,
		).
		// The cache filler/cleaner controllers are responsible for keep an in-memory representation of active
		// authenticators up to date.
		WithController(
			webhookcachefiller.New(
				c.ServerInstallationInfo.Namespace,
				c.AuthenticatorCache,
				client.PinnipedConcierge,
				informers.pinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				informers.installationNamespaceK8s.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
				clock.RealClock{},
				plog.New(),
				ptls.NewDialer(),
				proxydetect.New(),
			),
			singletonWorker,
		).
		WithController(
			jwtcachefiller.New(
				c.ServerInstallationInfo.Namespace,
				c.AuthenticatorCache,
				client.PinnipedConcierge,
				informers.pinniped.Authentication().V1alpha1().JWTAuthenticators(),
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				informers.installationNamespaceK8s.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
				clock.RealClock{},
				plog.New(),
			),
			singletonWorker,
		).
		WithController(
			cachecleaner.New(
				c.AuthenticatorCache,
				informers.pinniped.Authentication().V1alpha1().WebhookAuthenticators(),
				informers.pinniped.Authentication().V1alpha1().JWTAuthenticators(),
				plog.New(),
			),
			singletonWorker,
		).

		// The impersonator configuration controller dynamically configures the impersonation proxy feature.
		WithController(
			impersonatorconfig.NewImpersonatorConfigController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.CredentialIssuer,
				client.Kubernetes,
				client.PinnipedConcierge,
				informers.pinniped.Config().V1alpha1().CredentialIssuers(),
				informers.installationNamespaceK8s.Core().V1().Services(),
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				c.ImpersonationProxyServerPort,
				c.NamesConfig.ImpersonationLoadBalancerService,
				c.NamesConfig.ImpersonationClusterIPService,
				c.NamesConfig.ImpersonationTLSCertificateSecret,
				c.NamesConfig.ImpersonationCACertificateSecret,
				c.Labels,
				clock.RealClock{},
				impersonator.New,
				c.NamesConfig.ImpersonationSignerSecret,
				c.ImpersonationSigningCertProvider,
				plog.New(),
				c.ImpersonationProxyTokenCache,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsCreatorController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ImpersonationSignerSecret,
				c.Labels,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				365*24*time.Hour, // 1 year hard coded value
				"Pinniped Impersonation Proxy Signer CA",
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
				365*24*time.Hour-time.Hour, // 1 year minus 1 hour hard coded value (i.e. wait until the last moment to break the signer)
				apicerts.CACertificateSecretKey,
				plog.New(),
			),
			singletonWorker,
		).
		WithController(
			serviceaccounttokencleanup.NewLegacyServiceAccountTokenCleanupController(
				c.ServerInstallationInfo.Namespace,
				c.NamesConfig.ImpersonationProxyLegacySecret,
				client.Kubernetes,
				informers.installationNamespaceK8s.Core().V1().Secrets(),
				controllerlib.WithInformer,
				plog.New(),
			),
			singletonWorker,
		)

	return controllerinit.Prepare(controllerManager.Start, leaderElector,
		informers.kubePublicNamespaceK8s,
		informers.kubeSystemNamespaceK8s,
		informers.installationNamespaceK8s,
		informers.pinniped,
	), nil
}

type informers struct {
	kubePublicNamespaceK8s   k8sinformers.SharedInformerFactory
	kubeSystemNamespaceK8s   k8sinformers.SharedInformerFactory
	installationNamespaceK8s k8sinformers.SharedInformerFactory
	pinniped                 conciergeinformers.SharedInformerFactory
}

// Create the informers that will be used by the controllers.
func createInformers(
	serverInstallationNamespace string,
	k8sClient kubernetes.Interface,
	pinnipedClient conciergeclientset.Interface,
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
		pinniped: conciergeinformers.NewSharedInformerFactoryWithOptions(
			pinnipedClient,
			defaultResyncInterval,
		),
	}
}
