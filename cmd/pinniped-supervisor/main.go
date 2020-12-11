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

	"go.pinniped.dev/internal/secret"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controller/supervisorconfig/secretgenerator"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatcher"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/manager"
	"go.pinniped.dev/internal/plog"
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
	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorconfig.NewOIDCProviderWatcherController(
				issuerManager,
				clock.RealClock{},
				pinnipedClient,
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
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
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewJWKSObserverController(
				dynamicJWKSProvider,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			supervisorconfig.NewTLSCertObserverController(
				dynamicTLSCertProvider,
				cfg.NamesConfig.DefaultTLSCertificateSecret,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviders(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		).
		WithController(
			secretgenerator.New(
				supervisorDeployment,
				kubeClient,
				kubeInformers.Core().V1().Secrets(),
				func(secret []byte) {
					plog.Debug("setting csrf cookie secret")
					secretCache.SetCSRFCookieEncoderHashKey(secret)
				},
			),
			singletonWorker,
		).
		WithController(
			upstreamwatcher.New(
				dynamicUpstreamIDPProvider,
				pinnipedClient,
				pinnipedInformers.IDP().V1alpha1().UpstreamOIDCProviders(),
				kubeInformers.Core().V1().Secrets(),
				klogr.New()),
			singletonWorker)

	kubeInformers.Start(ctx.Done())
	pinnipedInformers.Start(ctx.Done())

	// Wait until the caches are synced before returning.
	kubeInformers.WaitForCacheSync(ctx.Done())
	pinnipedInformers.WaitForCacheSync(ctx.Done())

	go controllerManager.Start(ctx)
}

func getSupervisorDeployment(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	podInfo *downward.PodInfo,
) (*appsv1.Deployment, error) {
	ns := podInfo.Namespace

	pod, err := kubeClient.CoreV1().Pods(ns).Get(ctx, podInfo.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get pod: %w", err)
	}

	podOwner := metav1.GetControllerOf(pod)
	if podOwner == nil {
		return nil, fmt.Errorf("pod %s/%s is missing owner", ns, podInfo.Name)
	}

	rs, err := kubeClient.AppsV1().ReplicaSets(ns).Get(ctx, podOwner.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get replicaset: %w", err)
	}

	rsOwner := metav1.GetControllerOf(rs)
	if rsOwner == nil {
		return nil, fmt.Errorf("replicaset %s/%s is missing owner", ns, podInfo.Name)
	}

	d, err := kubeClient.AppsV1().Deployments(ns).Get(ctx, rsOwner.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get deployment: %w", err)
	}

	return d, nil
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

func run(podInfo *downward.PodInfo, cfg *supervisor.Config) error {
	serverInstallationNamespace := podInfo.Namespace

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
	dynamicUpstreamIDPProvider := provider.NewDynamicUpstreamIDPProvider()
	secretCache := secret.Cache{}

	// OIDC endpoints will be served by the oidProvidersManager, and any non-OIDC paths will fallback to the healthMux.
	oidProvidersManager := manager.NewManager(
		healthMux,
		dynamicJWKSProvider,
		dynamicUpstreamIDPProvider,
		&secretCache,
		kubeClient.CoreV1().Secrets(serverInstallationNamespace),
	)

	supervisorDeployment, err := getSupervisorDeployment(ctx, kubeClient, podInfo)
	if err != nil {
		return fmt.Errorf("cannot get supervisor deployment: %w", err)
	}

	startControllers(
		ctx,
		cfg,
		oidProvidersManager,
		dynamicJWKSProvider,
		dynamicTLSCertProvider,
		dynamicUpstreamIDPProvider,
		&secretCache,
		supervisorDeployment,
		kubeClient,
		pinnipedClient,
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
