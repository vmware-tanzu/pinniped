// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
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
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controller/supervisorconfig/activedirectoryupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/generator"
	"go.pinniped.dev/internal/controller/supervisorconfig/ldapupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorconfig/oidcupstreamwatcher"
	"go.pinniped.dev/internal/controller/supervisorstorage"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/deploymentref"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/leaderelection"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/manager"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/secret"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

func startServer(ctx context.Context, shutdown *sync.WaitGroup, l net.Listener, handler http.Handler) {
	handler = genericapifilters.WithWarningRecorder(handler)
	handler = withBootstrapPaths(handler, "/healthz") // only health checks are allowed for bootstrap connections

	server := http.Server{
		Handler:     handler,
		ConnContext: withBootstrapConnCtx,
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
	issuerManager *manager.Manager,
	dynamicJWKSProvider jwks.DynamicJWKSProvider,
	dynamicTLSCertProvider provider.DynamicTLSCertProvider,
	dynamicUpstreamIDPProvider provider.DynamicUpstreamIDPProvider,
	secretCache *secret.Cache,
	supervisorDeployment *appsv1.Deployment,
	kubeClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
	kubeInformers kubeinformers.SharedInformerFactory,
	pinnipedInformers pinnipedinformers.SharedInformerFactory,
	leaderElector controllerinit.RunnerWrapper,
) controllerinit.RunnerBuilder {
	federationDomainInformer := pinnipedInformers.Config().V1alpha1().FederationDomains()
	secretInformer := kubeInformers.Core().V1().Secrets()

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
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewFederationDomainWatcherController(
				issuerManager,
				clock.RealClock{},
				pinnipedClient,
				federationDomainInformer,
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
				func(fd *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
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
				func(fd *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
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
				func(fd *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference {
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
				plog.Logr(), // nolint: staticcheck  // old controller with lots of log statements
				controllerlib.WithInformer,
			),
			singletonWorker).
		WithController(
			ldapupstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				secretInformer,
				controllerlib.WithInformer,
			),
			singletonWorker).
		WithController(
			activedirectoryupstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				secretInformer,
				controllerlib.WithInformer,
			),
			singletonWorker)

	return controllerinit.Prepare(controllerManager.Start, leaderElector, kubeInformers, pinnipedInformers)
}

func startControllers(ctx context.Context, shutdown *sync.WaitGroup, buildControllers controllerinit.RunnerBuilder) error {
	runControllers, err := buildControllers(ctx)
	if err != nil {
		return fmt.Errorf("cannot create run controller func: %w", err)
	}

	shutdown.Add(1)
	go func() {
		defer shutdown.Done()

		runControllers(ctx)
	}()

	return nil
}

//nolint:funlen
func runSupervisor(ctx context.Context, podInfo *downward.PodInfo, cfg *supervisor.Config) error {
	serverInstallationNamespace := podInfo.Namespace

	dref, supervisorDeployment, supervisorPod, err := deploymentref.New(podInfo)
	if err != nil {
		return fmt.Errorf("cannot create deployment ref: %w", err)
	}

	opts := []kubeclient.Option{
		dref,
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

	kubeInformers := kubeinformers.NewSharedInformerFactoryWithOptions(
		client.Kubernetes,
		defaultResyncInterval,
		kubeinformers.WithNamespace(serverInstallationNamespace),
	)

	pinnipedInformers := pinnipedinformers.NewSharedInformerFactoryWithOptions(
		client.PinnipedSupervisor,
		defaultResyncInterval,
		pinnipedinformers.WithNamespace(serverInstallationNamespace),
	)

	// Serve the /healthz endpoint and make all other paths result in 404.
	healthMux := http.NewServeMux()
	healthMux.Handle("/healthz", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))

	dynamicJWKSProvider := jwks.NewDynamicJWKSProvider()
	dynamicTLSCertProvider := provider.NewDynamicTLSCertProvider()
	dynamicUpstreamIDPProvider := provider.NewDynamicUpstreamIDPProvider()
	secretCache := secret.Cache{}

	// OIDC endpoints will be served by the oidProvidersManager, and any non-OIDC paths will fallback to the healthMux.
	oidProvidersManager := manager.NewManager(
		healthMux,
		dynamicJWKSProvider,
		dynamicUpstreamIDPProvider,
		&secretCache,
		clientWithoutLeaderElection.Kubernetes.CoreV1().Secrets(serverInstallationNamespace), // writes to kube storage are allowed for non-leaders
	)

	buildControllersFunc := prepareControllers(
		cfg,
		oidProvidersManager,
		dynamicJWKSProvider,
		dynamicTLSCertProvider,
		dynamicUpstreamIDPProvider,
		&secretCache,
		supervisorDeployment,
		client.Kubernetes,
		client.PinnipedSupervisor,
		kubeInformers,
		pinnipedInformers,
		leaderElector,
	)

	shutdown := &sync.WaitGroup{}

	if err := startControllers(ctx, shutdown, buildControllersFunc); err != nil {
		return err
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
		startServer(ctx, shutdown, httpListener, oidProvidersManager)
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

			defaultCert := dynamicTLSCertProvider.GetDefaultTLSCert()

			if plog.Enabled(plog.LevelTrace) { // minor CPU optimization as this is generally just noise
				host, port, _ := net.SplitHostPort(info.Conn.LocalAddr().String()) // error is safe to ignore here

				plog.Trace("GetCertificate called",
					"info.ServerName", info.ServerName,
					"foundSNICert", cert != nil,
					"foundDefaultCert", defaultCert != nil,
					"host", host,
					"port", port,
				)
			}

			if cert == nil {
				cert = defaultCert
			}

			if cert == nil {
				setIsBootstrapConn(info.Context()) // make this connection only work for bootstrap requests
				cert = bootstrapCert
			}

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
		startServer(ctx, shutdown, httpsListener, oidProvidersManager)
		plog.Debug("supervisor https listener started", "address", httpsListener.Addr().String())
	}

	plog.Debug("supervisor started")
	defer plog.Debug("supervisor exiting")

	shutdown.Wait()

	return nil
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
		"version", versionInfo(version.Get()),
		"arguments", os.Args,
	)

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(os.Args[1])
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}

	ctx := signalCtx()

	// Read the server config file.
	cfg, err := supervisor.FromPath(ctx, os.Args[2])
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	return runSupervisor(ctx, podInfo, cfg)
}

func Main() {
	if err := main(); err != nil {
		plog.Fatal(err)
	}
}

type versionInfo apimachineryversion.Info // hide .String() method from plog
