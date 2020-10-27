// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/manager"
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
			klog.InfoS("server exited", "err", err)
		case <-ctx.Done():
			klog.InfoS("server context cancelled", "err", ctx.Err())
			if err := server.Shutdown(context.Background()); err != nil {
				klog.InfoS("server shutdown failed", "err", err)
			}
		}
	}()
}

func waitForSignal() os.Signal {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	return <-signalCh
}

func startControllers(
	ctx context.Context,
	cfg *supervisor.Config,
	issuerManager *manager.Manager,
	dynamicJWKSProvider jwks.DynamicJWKSProvider,
	dynamicTLSCertProvider provider.DynamicTLSCertProvider,
	kubeClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
	kubeInformers kubeinformers.SharedInformerFactory,
	pinnipedInformers pinnipedinformers.SharedInformerFactory,
) {
	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorconfig.NewOIDCProviderConfigWatcherController(
				issuerManager,
				clock.RealClock{},
				pinnipedClient,
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewJWKSWriterController(
				cfg.Labels,
				kubeClient,
				pinnipedClient,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewJWKSObserverController(
				dynamicJWKSProvider,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewTLSCertObserverController(
				dynamicTLSCertProvider,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	kubeInformers.Start(ctx.Done())
	pinnipedInformers.Start(ctx.Done())

	// Wait until the caches are synced before returning.
	kubeInformers.WaitForCacheSync(ctx.Done())
	pinnipedInformers.WaitForCacheSync(ctx.Done())

	go controllerManager.Start(ctx)
}

func newClients() (kubernetes.Interface, pinnipedclientset.Interface, error) {
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// Connect to the core Kubernetes API.
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create kube client: %w", err)
	}

	// Connect to the Pinniped API.
	pinnipedClient, err := pinnipedclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create pinniped client: %w", err)
	}

	return kubeClient, pinnipedClient, nil
}

func run(serverInstallationNamespace string, cfg *supervisor.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeClient, pinnipedClient, err := newClients()
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	kubeInformers := kubeinformers.NewSharedInformerFactoryWithOptions(
		kubeClient,
		defaultResyncInterval,
		kubeinformers.WithNamespace(serverInstallationNamespace),
	)

	pinnipedInformers := pinnipedinformers.NewSharedInformerFactoryWithOptions(
		pinnipedClient,
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

	// OIDC endpoints will be served by the oidProvidersManager, and any non-OIDC paths will fallback to the healthMux.
	oidProvidersManager := manager.NewManager(healthMux, dynamicJWKSProvider)

	startControllers(
		ctx,
		cfg,
		oidProvidersManager,
		dynamicJWKSProvider,
		dynamicTLSCertProvider,
		kubeClient,
		pinnipedClient,
		kubeInformers,
		pinnipedInformers,
	)

	//nolint: gosec // Intentionally binding to all network interfaces.
	httpListener, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer httpListener.Close()
	start(ctx, httpListener, oidProvidersManager)

	//nolint: gosec // Intentionally binding to all network interfaces.
	httpsListener, err := tls.Listen("tcp", ":443", &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			klog.InfoS("GetCertificate called", "info.ServerName", info.ServerName)
			return dynamicTLSCertProvider.GetTLSCert(strings.ToLower(info.ServerName)), nil
		},
	})
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer httpsListener.Close()
	start(ctx, httpsListener, oidProvidersManager)

	klog.InfoS("supervisor is ready",
		"httpAddress", httpListener.Addr().String(),
		"httpsAddress", httpsListener.Addr().String(),
	)

	gotSignal := waitForSignal()
	klog.InfoS("supervisor exiting", "signal", gotSignal)

	return nil
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

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

	if err := run(podInfo.Namespace, cfg); err != nil {
		klog.Fatal(err)
	}
}
