// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"

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
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/deploymentref"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
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

func start(ctx context.Context, l net.Listener, handler http.Handler) {
	server := http.Server{Handler: handler}

	errCh := make(chan error)
	go func() {
		errCh <- server.Serve(l)
	}()

	go func() {
		select {
		case err := <-errCh:
			plog.Debug("server exited", "err", err)
		case <-ctx.Done():
			plog.Debug("server context cancelled", "err", ctx.Err())
			if err := server.Shutdown(context.Background()); err != nil {
				plog.Debug("server shutdown failed", "err", err)
			}
		}
	}()
}

func waitForSignal() os.Signal {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	return <-signalCh
}

//nolint:funlen
func startControllers(
	ctx context.Context,
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
) {
	federationDomainInformer := pinnipedInformers.Config().V1alpha1().FederationDomains()
	secretInformer := kubeInformers.Core().V1().Secrets()

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorstorage.GarbageCollectorController(
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
				klogr.New(),
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

	kubeInformers.Start(ctx.Done())
	pinnipedInformers.Start(ctx.Done())

	// Wait until the caches are synced before returning.
	kubeInformers.WaitForCacheSync(ctx.Done())
	pinnipedInformers.WaitForCacheSync(ctx.Done())

	go controllerManager.Start(ctx)
}

func run(podInfo *downward.PodInfo, cfg *supervisor.Config) error {
	serverInstallationNamespace := podInfo.Namespace

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dref, supervisorDeployment, err := deploymentref.New(podInfo)
	if err != nil {
		return fmt.Errorf("cannot create deployment ref: %w", err)
	}

	client, err := kubeclient.New(
		dref,
		kubeclient.WithMiddleware(groupsuffix.New(*cfg.APIGroupSuffix)),
	)
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
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
		client.Kubernetes.CoreV1().Secrets(serverInstallationNamespace),
	)

	startControllers(
		ctx,
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
	)

	//nolint: gosec // Intentionally binding to all network interfaces.
	httpListener, err := net.Listen("tcp", ":8080")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer func() { _ = httpListener.Close() }()
	start(ctx, httpListener, oidProvidersManager)

	//nolint: gosec // Intentionally binding to all network interfaces.
	httpsListener, err := tls.Listen("tcp", ":8443", &tls.Config{
		MinVersion: tls.VersionTLS12, // Allow v1.2 because clients like the default `curl` on MacOS don't support 1.3 yet.
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := dynamicTLSCertProvider.GetTLSCert(strings.ToLower(info.ServerName))
			defaultCert := dynamicTLSCertProvider.GetDefaultTLSCert()
			plog.Debug("GetCertificate called for port 8443",
				"info.ServerName", info.ServerName,
				"foundSNICert", cert != nil,
				"foundDefaultCert", defaultCert != nil,
			)
			if cert == nil {
				cert = defaultCert
			}
			return cert, nil
		},
	})
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer func() { _ = httpsListener.Close() }()
	start(ctx, httpsListener, oidProvidersManager)

	plog.Debug("supervisor is ready",
		"httpAddress", httpListener.Addr().String(),
		"httpsAddress", httpsListener.Addr().String(),
	)

	gotSignal := waitForSignal()
	plog.Debug("supervisor exiting", "signal", gotSignal)

	return nil
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()
	plog.RemoveKlogGlobalFlags() // move this whenever the below code gets refactored to use cobra

	klog.Infof("Running %s at %#v", rest.DefaultKubernetesUserAgent(), version.Get())
	klog.Infof("Command-line arguments were: %s %s %s", os.Args[0], os.Args[1], os.Args[2])

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(os.Args[1])
	if err != nil {
		klog.Fatal(fmt.Errorf("could not read pod metadata: %w", err))
	}

	// Read the server config file.
	cfg, err := supervisor.FromPath(os.Args[2])
	if err != nil {
		klog.Fatal(fmt.Errorf("could not load config: %w", err))
	}

	if err := run(podInfo, cfg); err != nil {
		klog.Fatal(err)
	}
}
