// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package server defines the entrypoint for the Pinniped Supervisor server.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joshlf/go-acl"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/cache"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	openapinamer "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/utils/clock"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	"go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	supervisorinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	supervisoropenapi "go.pinniped.dev/generated/latest/client/supervisor/openapi"
	"go.pinniped.dev/internal/admissionpluginconfig"
	"go.pinniped.dev/internal/apiserviceref"
	"go.pinniped.dev/internal/config/featuregates"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controller/supervisorconfig/activedirectoryupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/generator"
	"go.pinniped.dev/internal/controller/supervisorconfig/githubupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/ldapupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/oidcclientwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/oidcupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorstorage"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/deploymentref"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/federationdomain/dynamictlscertprovider"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/endpointsmanager"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/leaderelection"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/pversion"
	"go.pinniped.dev/internal/secret"
	"go.pinniped.dev/internal/supervisor/apiserver"
	supervisorscheme "go.pinniped.dev/internal/supervisor/scheme"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

func startServer(ctx context.Context, shutdown *sync.WaitGroup, l net.Listener, handler http.Handler) {
	handler = genericapifilters.WithWarningRecorder(handler)
	handler = withBootstrapPaths(handler, "/healthz") // only health checks are allowed for bootstrap connections

	server := http.Server{
		Handler:           handler,
		ConnContext:       withBootstrapConnCtx,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdown.Add(1)
	go func() {
		defer shutdown.Done()

		err := server.Serve(l)
		plog.Debug("server exited", "err", err)
	}()

	shutdown.Add(1)
	go func() {
		defer shutdown.Done()

		<-ctx.Done()
		plog.Debug("server context cancelled", "err", ctx.Err())

		// allow up to a minute grace period for active connections to return to idle
		connectionsCtx, connectionsCancel := context.WithTimeout(context.Background(), time.Minute)
		defer connectionsCancel()

		if err := server.Shutdown(connectionsCtx); err != nil {
			plog.Debug("server shutdown failed", "err", err)
		}
	}()
}

func signalCtx() context.Context {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()

		s := <-signalCh
		plog.Debug("saw signal", "signal", s)
	}()

	return ctx
}

//nolint:funlen
func prepareControllers(
	cfg *supervisor.Config,
	issuerManager *endpointsmanager.Manager,
	dynamicJWKSProvider jwks.DynamicJWKSProvider,
	dynamicTLSCertProvider dynamictlscertprovider.DynamicTLSCertProvider,
	dynamicUpstreamIDPProvider dynamicupstreamprovider.DynamicUpstreamIDPProvider,
	dynamicServingCertProvider dynamiccert.Private,
	secretCache *secret.Cache,
	supervisorDeployment *appsv1.Deployment,
	kubeClient kubernetes.Interface,
	pinnipedClient supervisorclientset.Interface,
	aggregatorClient aggregatorclient.Interface,
	kubeInformers k8sinformers.SharedInformerFactory,
	pinnipedInformers supervisorinformers.SharedInformerFactory,
	leaderElector controllerinit.RunnerWrapper,
	podInfo *downward.PodInfo,
) controllerinit.RunnerBuilder {
	const certificateName string = "pinniped-supervisor-api-tls-serving-certificate"
	clientSecretSupervisorGroupData := groupsuffix.SupervisorAggregatedGroups(*cfg.APIGroupSuffix)
	federationDomainInformer := pinnipedInformers.Config().V1alpha1().FederationDomains()
	oidcClientInformer := pinnipedInformers.Config().V1alpha1().OIDCClients()
	secretInformer := kubeInformers.Core().V1().Secrets()
	configMapInformer := kubeInformers.Core().V1().ConfigMaps()

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorstorage.GarbageCollectorController(
				dynamicUpstreamIDPProvider,
				clock.RealClock{},
				kubeClient,
				secretInformer,
				controllerlib.WithInformer,
				plog.New(),
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewFederationDomainWatcherController(
				issuerManager,
				*cfg.APIGroupSuffix,
				clock.RealClock{},
				pinnipedClient,
				federationDomainInformer,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().GitHubIdentityProviders(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewJWKSWriterController(
				cfg.Labels,
				kubeClient,
				pinnipedClient,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewJWKSObserverController(
				dynamicJWKSProvider,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewTLSCertObserverController(
				dynamicTLSCertProvider,
				cfg.NamesConfig.DefaultTLSCertificateSecret,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			generator.NewSupervisorSecretsController(
				supervisorDeployment,
				cfg.Labels,
				kubeClient,
				secretInformer,
				func(secret []byte) {
					plog.Debug("setting csrf cookie secret")
					secretCache.SetCSRFCookieEncoderHashKey(secret)
				},
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
			),
			singletonWorker,
		).
		WithController(
			generator.NewFederationDomainSecretsController(
				generator.NewSymmetricSecretHelper(
					"pinniped-oidc-provider-hmac-key-",
					cfg.Labels,
					rand.Reader,
					generator.SecretUsageTokenSigningKey,
					func(federationDomainIssuer string, symmetricKey []byte) {
						plog.Debug("setting hmac secret", "issuer", federationDomainIssuer)
						secretCache.SetTokenHMACKey(federationDomainIssuer, symmetricKey)
					},
				),
				func(fd *supervisorconfigv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
					return &fd.Secrets.TokenSigningKey
				},
				kubeClient,
				pinnipedClient,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			generator.NewFederationDomainSecretsController(
				generator.NewSymmetricSecretHelper(
					"pinniped-oidc-provider-upstream-state-signature-key-",
					cfg.Labels,
					rand.Reader,
					generator.SecretUsageStateSigningKey,
					func(federationDomainIssuer string, symmetricKey []byte) {
						plog.Debug("setting state signature key", "issuer", federationDomainIssuer)
						secretCache.SetStateEncoderHashKey(federationDomainIssuer, symmetricKey)
					},
				),
				func(fd *supervisorconfigv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
					return &fd.Secrets.StateSigningKey
				},
				kubeClient,
				pinnipedClient,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			generator.NewFederationDomainSecretsController(
				generator.NewSymmetricSecretHelper(
					"pinniped-oidc-provider-upstream-state-encryption-key-",
					cfg.Labels,
					rand.Reader,
					generator.SecretUsageStateEncryptionKey,
					func(federationDomainIssuer string, symmetricKey []byte) {
						plog.Debug("setting state encryption key", "issuer", federationDomainIssuer)
						secretCache.SetStateEncoderBlockKey(federationDomainIssuer, symmetricKey)
					},
				),
				func(fd *supervisorconfigv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
					return &fd.Secrets.StateEncryptionKey
				},
				kubeClient,
				pinnipedClient,
				secretInformer,
				federationDomainInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			oidcupstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				secretInformer,
				configMapInformer,
				plog.New(),
				controllerlib.WithInformer,
				cache.NewExpiring(),
			),
			singletonWorker).
		WithController(
			ldapupstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				secretInformer,
				configMapInformer,
				controllerlib.WithInformer,
			),
			singletonWorker).
		WithController(
			activedirectoryupstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				secretInformer,
				configMapInformer,
				controllerlib.WithInformer,
			),
			singletonWorker).
		WithController(
			githubupstreamwatcher.New(
				podInfo.Namespace,
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().GitHubIdentityProviders(),
				secretInformer,
				configMapInformer,
				plog.New(),
				controllerlib.WithInformer,
				clock.RealClock{},
				githubupstreamwatcher.ProbeURL,
				cache.NewExpiring(),
			),
			singletonWorker).
		WithController(
			apicerts.NewCertsManagerController(
				podInfo.Namespace,
				certificateName,
				cfg.Labels,
				kubeClient,
				secretInformer,
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				365*24*time.Hour, // about one year
				"Pinniped Supervisor Aggregation CA",
				cfg.NamesConfig.APIService,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewAPIServiceUpdaterController(
				podInfo.Namespace,
				certificateName,
				clientSecretSupervisorGroupData.APIServiceName(),
				aggregatorClient,
				secretInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				podInfo.Namespace,
				certificateName,
				dynamicServingCertProvider,
				secretInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsExpirerController(
				podInfo.Namespace,
				certificateName,
				kubeClient,
				secretInformer,
				controllerlib.WithInformer,
				9*30*24*time.Hour, // about 9 months
				apicerts.TLSCertificateChainSecretKey,
				plog.New(),
			),
			singletonWorker,
		).
		WithController(
			oidcclientwatcher.NewOIDCClientWatcherController(
				pinnipedClient,
				secretInformer,
				oidcClientInformer,
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	return controllerinit.Prepare(controllerManager.Start, leaderElector, kubeInformers, pinnipedInformers)
}

// Boot the aggregated API server, which will in turn boot the controllers. Also open the appropriate network ports
// and start serving the health endpoint and the endpoints of the configured FederationDomains.
// In practice, the ctx passed in should be one which will be cancelled when the process receives SIGTERM or SIGINT.
func runSupervisor(ctx context.Context, podInfo *downward.PodInfo, cfg *supervisor.Config) error { //nolint:funlen
	// We tried to enable the feature gate from https://github.com/kubernetes/kubernetes/pull/121120,
	// but it causes errors when there are lots of parallel anonymous requests for our aggregated API endpoints.
	// Make sure https://github.com/kubernetes/kubernetes/issues/122308 is resolved before enabling this.
	featuregates.DisableKubeFeatureGate(features.UnauthenticatedHTTP2DOSMitigation)

	serverInstallationNamespace := podInfo.Namespace
	clientSecretSupervisorGroupData := groupsuffix.SupervisorAggregatedGroups(*cfg.APIGroupSuffix)

	apiServiceRef, err := apiserviceref.New(clientSecretSupervisorGroupData.APIServiceName())
	if err != nil {
		return fmt.Errorf("cannot create API service ref: %w", err)
	}

	dref, supervisorDeployment, supervisorPod, err := deploymentref.New(podInfo)
	if err != nil {
		return fmt.Errorf("cannot create deployment ref: %w", err)
	}

	opts := []kubeclient.Option{
		dref,
		apiServiceRef,
		kubeclient.WithMiddleware(groupsuffix.New(*cfg.APIGroupSuffix)),
	}

	client, leaderElector, err := leaderelection.New(
		podInfo,
		supervisorDeployment,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	clientWithoutLeaderElection, err := kubeclient.New(opts...)
	if err != nil {
		return fmt.Errorf("cannot create k8s client without leader election: %w", err)
	}

	kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(
		client.Kubernetes,
		defaultResyncInterval,
		k8sinformers.WithNamespace(serverInstallationNamespace),
	)

	pinnipedInformers := supervisorinformers.NewSharedInformerFactoryWithOptions(
		client.PinnipedSupervisor,
		defaultResyncInterval,
		supervisorinformers.WithNamespace(serverInstallationNamespace),
	)

	// Serve the /healthz endpoint and make all other paths result in 404.
	healthMux := http.NewServeMux()
	healthMux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	dynamicServingCertProvider := dynamiccert.NewServingCert("supervisor-serving-cert")

	dynamicJWKSProvider := jwks.NewDynamicJWKSProvider()
	dynamicTLSCertProvider := dynamictlscertprovider.NewDynamicTLSCertProvider()
	dynamicUpstreamIDPProvider := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
	secretCache := secret.Cache{}

	// OIDC endpoints will be served by the endpoints manager, and any non-OIDC paths will fallback to the healthMux.
	oidProvidersManager := endpointsmanager.NewManager(
		healthMux,
		dynamicJWKSProvider,
		dynamicUpstreamIDPProvider,
		&secretCache,
		clientWithoutLeaderElection.Kubernetes.CoreV1().Secrets(serverInstallationNamespace), // writes to kube storage are allowed for non-leaders
		client.PinnipedSupervisor.ConfigV1alpha1().OIDCClients(serverInstallationNamespace),
		plog.New(),
		cfg.Audit,
	)

	// Get the "real" name of the client secret supervisor API group (i.e., the API group name with the
	// injected suffix).
	scheme, clientSecretGV := supervisorscheme.New(*cfg.APIGroupSuffix)

	buildControllersFunc := prepareControllers(
		cfg,
		oidProvidersManager,
		dynamicJWKSProvider,
		dynamicTLSCertProvider,
		dynamicUpstreamIDPProvider,
		dynamicServingCertProvider,
		&secretCache,
		supervisorDeployment,
		client.Kubernetes,
		client.PinnipedSupervisor,
		client.Aggregation,
		kubeInformers,
		pinnipedInformers,
		leaderElector,
		podInfo,
	)

	shutdown := &sync.WaitGroup{}

	// Get the aggregated API server config.
	aggregatedAPIServerConfig, err := getAggregatedAPIServerConfig(
		dynamicServingCertProvider,
		buildControllersFunc,
		*cfg.APIGroupSuffix,
		*cfg.AggregatedAPIServerPort,
		scheme,
		clientSecretGV,
		clientWithoutLeaderElection.Kubernetes.CoreV1().Secrets(serverInstallationNamespace),
		client.PinnipedSupervisor.ConfigV1alpha1().OIDCClients(serverInstallationNamespace),
		serverInstallationNamespace,
	)
	if err != nil {
		return fmt.Errorf("could not configure aggregated API server: %w", err)
	}

	// Complete the aggregated API server config and make a server instance.
	server, err := aggregatedAPIServerConfig.Complete().New()
	if err != nil {
		return fmt.Errorf("could not create aggregated API server: %w", err)
	}

	if e := cfg.Endpoints.HTTP; e.Network != supervisor.NetworkDisabled {
		finishSetupPerms := maybeSetupUnixPerms(e, supervisorPod)

		httpListener, err := net.Listen(e.Network, e.Address)
		if err != nil {
			return fmt.Errorf("cannot create http listener with network %q and address %q: %w", e.Network, e.Address, err)
		}

		if err := finishSetupPerms(); err != nil {
			return fmt.Errorf("cannot setup http listener permissions for network %q and address %q: %w", e.Network, e.Address, err)
		}

		defer func() { _ = httpListener.Close() }()
		startServer(ctx, shutdown, httpListener, oidProvidersManager.HandlerChain())
		plog.Debug("supervisor http listener started", "address", httpListener.Addr().String())
	}

	if e := cfg.Endpoints.HTTPS; e.Network != supervisor.NetworkDisabled { //nolint:nestif
		finishSetupPerms := maybeSetupUnixPerms(e, supervisorPod)

		bootstrapCert, err := getBootstrapCert() // generate this in-memory once per process startup
		if err != nil {
			return fmt.Errorf("https listener bootstrap error: %w", err)
		}

		c := ptls.Default(nil)
		c.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := dynamicTLSCertProvider.GetTLSCert(strings.ToLower(info.ServerName))
			foundServerNameCert := cert != nil

			defaultCert := dynamicTLSCertProvider.GetDefaultTLSCert()

			if !foundServerNameCert {
				cert = defaultCert
			}

			// If we still don't have a cert for the request at this point, then using the bootstrapping cert,
			// but in that case also set the request to fail unless it is a health check request.
			usingBootstrapCert := false
			if cert == nil {
				usingBootstrapCert = true
				setIsBootstrapConn(info.Context()) // make this connection only work for bootstrap requests
				cert = bootstrapCert
			}

			// Emit logs visible at a higher level of logging than the default. Using Info level so the user
			// can safely configure a production Supervisor to show this message if they choose.
			plog.Info("choosing TLS cert for incoming request",
				"requestSNIServerName", info.ServerName,
				"foundCertForSNIServerNameFromFederationDomain", foundServerNameCert,
				"foundDefaultCertFromSecret", defaultCert != nil,
				"defaultCertSecretName", cfg.NamesConfig.DefaultTLSCertificateSecret,
				"servingBootstrapHealthzCert", usingBootstrapCert,
				"requestLocalAddr", info.Conn.LocalAddr().String(),
				"requestRemoteAddr", info.Conn.RemoteAddr().String(),
			)

			return cert, nil
		}

		httpsListener, err := tls.Listen(e.Network, e.Address, c)
		if err != nil {
			return fmt.Errorf("cannot create https listener with network %q and address %q: %w", e.Network, e.Address, err)
		}

		if err := finishSetupPerms(); err != nil {
			return fmt.Errorf("cannot setup https listener permissions for network %q and address %q: %w", e.Network, e.Address, err)
		}

		defer func() { _ = httpsListener.Close() }()
		startServer(ctx, shutdown, httpsListener, oidProvidersManager.HandlerChain())
		plog.Debug("supervisor https listener started", "address", httpsListener.Addr().String())
	}

	plog.Debug("supervisor started")
	defer plog.Debug("supervisor exiting")

	// Run the server. Its post-start hook will start the controllers. Its pre shutdown hook will be called when ctx is
	// cancelled, and that hook should graceful stop the controllers and give up the leader election lease. See the
	// code for these hooks in internal/supervisor/apiserver.go.
	err = server.GenericAPIServer.PrepareRun().RunWithContext(ctx)
	if err != nil {
		return err
	}
	shutdown.Wait()

	return nil
}

func getAggregatedAPIServerConfig(
	dynamicCertProvider dynamiccert.Private,
	buildControllers controllerinit.RunnerBuilder,
	apiGroupSuffix string,
	aggregatedAPIServerPort int64,
	scheme *runtime.Scheme,
	clientSecretSupervisorGroupVersion schema.GroupVersion,
	secrets corev1client.SecretInterface,
	oidcClients v1alpha1.OIDCClientInterface,
	serverInstallationNamespace string,
) (*apiserver.Config, error) {
	codecs := serializer.NewCodecFactory(scheme)

	// this is unused for now but it is a safe value that we could use in the future
	defaultEtcdPathPrefix := fmt.Sprintf("/pinniped-supervisor-registry/%s", apiGroupSuffix)

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		codecs.LegacyCodec(clientSecretSupervisorGroupVersion),
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider

	// This port is configurable. It should be safe to cast because the config reader already validated it.
	recommendedOptions.SecureServing.BindPort = int(aggregatedAPIServerPort)

	err := admissionpluginconfig.ConfigureAdmissionPlugins(recommendedOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to configure admission plugins on recommended options: %w", err)
	}

	// secure TLS for connections coming from and going to the Kube API server
	// this is best effort because not all options provide the right hooks to override TLS config
	// since our only client is the Kube API server, this uses the most secure TLS config
	prepareServerConfigFunc, err := ptls.SecureRecommendedOptions(recommendedOptions, kubeclient.Secure)
	if err != nil {
		return nil, fmt.Errorf("failed to secure recommended options: %w", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(codecs)
	// Add the generated openapi docs to the server config. Publishing openapi docs allows
	// `kubectl explain` to work for the Supervisor's aggregated API resources.
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
		supervisoropenapi.GetOpenAPIDefinitions, openapinamer.NewDefinitionNamer(scheme))
	// serverConfig.OpenAPIConfig.Info.InfoProps.Title = "Pinniped Supervisor"
	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(
		supervisoropenapi.GetOpenAPIDefinitions, openapinamer.NewDefinitionNamer(scheme))
	// serverConfig.OpenAPIV3Config.Info.InfoProps.Title = "Pinniped Supervisor"

	// Get ready to call recommendedOptions.ApplyTo(serverConfig) by preparing the
	// serverConfig using the function returned by the ptls package above.
	prepareServerConfigFunc(serverConfig)

	// Note that among other things, this ApplyTo() function copies
	// `recommendedOptions.SecureServing.ServerCert.GeneratedCert` into
	// `serverConfig.SecureServing.Cert` thus making `dynamicCertProvider`
	// the cert provider for the running server. The provider will be called
	// by the API machinery periodically. When the provider returns nil certs,
	// the API server will return "the server is currently unable to
	// handle the request" error responses for all incoming requests.
	// If the provider later starts returning certs, then the API server
	// will use them to handle the incoming requests successfully.
	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, fmt.Errorf("failed to apply recommended options: %w", err)
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			BuildControllersPostStartHook:      buildControllers,
			Scheme:                             scheme,
			NegotiatedSerializer:               codecs,
			ClientSecretSupervisorGroupVersion: clientSecretSupervisorGroupVersion,
			Secrets:                            secrets,
			OIDCClients:                        oidcClients,
			Namespace:                          serverInstallationNamespace,
		},
	}
	return apiServerConfig, nil
}

func maybeSetupUnixPerms(endpoint *supervisor.Endpoint, pod *corev1.Pod) func() error {
	if endpoint.Network != supervisor.NetworkUnix {
		return func() error { return nil }
	}

	_ = os.Remove(endpoint.Address) // empty dir volumes persist across container crashes

	return func() error {
		selfUser := int64(os.Getuid())
		var entries []acl.Entry
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext == nil ||
				container.SecurityContext.RunAsUser == nil ||
				*container.SecurityContext.RunAsUser == selfUser {
				continue
			}

			plog.Debug("adding write permission",
				"address", endpoint.Address,
				"uid", *container.SecurityContext.RunAsUser,
			)
			entries = append(entries, acl.Entry{
				Tag:       acl.TagUser,
				Qualifier: strconv.FormatInt(*container.SecurityContext.RunAsUser, 10),
				Perms:     2, // write permission
			})
		}
		return acl.Add(endpoint.Address, entries...) // allow all containers in the pod to write to the socket
	}
}

func main() error { // return an error instead of plog.Fatal to allow defer statements to run
	defer plog.Setup()()

	plog.Always("Running supervisor",
		"user-agent", rest.DefaultKubernetesUserAgent(),
		"version", versionInfo(pversion.Get()),
		"arguments", os.Args,
	)

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(os.Args[1])
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}

	ctx := signalCtx()

	// Read the server config file.
	cfg, err := supervisor.FromPath(ctx, os.Args[2], ptls.SetUserConfiguredAllowedCipherSuitesForTLSOneDotTwo)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	// The above server config should have set the allowed ciphers global, so now log the ciphers for all profiles.
	ptls.LogAllProfiles(plog.New())

	return runSupervisor(ctx, podInfo, cfg)
}

func Main() {
	if err := main(); err != nil {
		plog.Fatal(err)
	}
}

type versionInfo apimachineryversion.Info // hide .String() method from plog
