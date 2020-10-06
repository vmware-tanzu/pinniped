// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/controller/supervisorconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/downward"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

type helloWorld struct{}

func (w *helloWorld) start(ctx context.Context, l net.Listener) error {
	server := http.Server{
		Handler: w,
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

	return nil
}

func (w *helloWorld) ServeHTTP(rsp http.ResponseWriter, req *http.Request) {
	// TODO this is just a placeholder to allow manually testing that this is reachable; we don't want a hello world endpoint
	defer req.Body.Close()
	_, _ = fmt.Fprintf(rsp, "Hello, world!")
}

func waitForSignal() os.Signal {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	return <-signalCh
}

func startControllers(
	ctx context.Context,
	kubeClient kubernetes.Interface,
	kubeInformers kubeinformers.SharedInformerFactory,
	serverInstallationNamespace string,
	staticConfig StaticConfig,
) {
	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			supervisorconfig.NewDynamicConfigWatcherController(
				serverInstallationNamespace,
				staticConfig.NamesConfig.DynamicConfigMap,
				kubeClient,
				kubeInformers.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	kubeInformers.Start(ctx.Done())

	go controllerManager.Start(ctx)
}

func newK8sClient() (kubernetes.Interface, error) {
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// Connect to the core Kubernetes API.
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	return kubeClient, nil
}

func run(serverInstallationNamespace string, staticConfig StaticConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeClient, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	kubeInformers := kubeinformers.NewSharedInformerFactoryWithOptions(
		kubeClient,
		defaultResyncInterval,
		kubeinformers.WithNamespace(serverInstallationNamespace),
	)

	startControllers(ctx, kubeClient, kubeInformers, serverInstallationNamespace, staticConfig)

	//nolint: gosec // Intentionally binding to all network interfaces.
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer l.Close()

	helloHandler := &helloWorld{}
	err = helloHandler.start(ctx, l)
	if err != nil {
		return fmt.Errorf("cannot start webhook: %w", err)
	}
	klog.InfoS("supervisor is ready", "address", l.Addr().String())

	gotSignal := waitForSignal()
	klog.InfoS("supervisor exiting", "signal", gotSignal)

	return nil
}

type StaticConfig struct {
	NamesConfig NamesConfigSpec `json:"names"`
}

type NamesConfigSpec struct {
	DynamicConfigMap string `json:"dynamicConfigMap"`
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

	// Read static config.
	data, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		klog.Fatal(fmt.Errorf("read file: %w", err))
	}
	var staticConfig StaticConfig
	if err := yaml.Unmarshal(data, &staticConfig); err != nil {
		klog.Fatal(fmt.Errorf("decode yaml: %w", err))
	}

	if err := run(podInfo.Namespace, staticConfig); err != nil {
		klog.Fatal(err)
	}
}
