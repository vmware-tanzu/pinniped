// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/issuerprovider"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

func start(ctx context.Context, l net.Listener, discoveryHandler http.Handler) {
	mux := http.NewServeMux()
	mux.Handle(oidc.WellKnownURLPath, discoveryHandler)
	server := http.Server{
		Handler: mux,
	}

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
	issuerProvider *issuerprovider.Provider,
	pinnipedInformers pinnipedinformers.SharedInformerFactory,
) {
	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorconfig.NewDynamicConfigWatcherController(
				issuerProvider,
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	pinnipedInformers.Start(ctx.Done())

	go controllerManager.Start(ctx)
}

func newPinnipedClient() (pinnipedclientset.Interface, error) {
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// Connect to the core Kubernetes API.
	pinnipedClient, err := pinnipedclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	return pinnipedClient, nil
}

func run(serverInstallationNamespace string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pinnipedClient, err := newPinnipedClient()
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	pinnipedInformers := pinnipedinformers.NewSharedInformerFactoryWithOptions(
		pinnipedClient,
		defaultResyncInterval,
		pinnipedinformers.WithNamespace(serverInstallationNamespace),
	)

	issuerProvider := issuerprovider.New()
	startControllers(ctx, issuerProvider, pinnipedInformers)

	//nolint: gosec // Intentionally binding to all network interfaces.
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer l.Close()

	start(ctx, l, discovery.New(issuerProvider))
	klog.InfoS("supervisor is ready", "address", l.Addr().String())

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

	if err := run(podInfo.Namespace); err != nil {
		klog.Fatal(err)
	}
}
