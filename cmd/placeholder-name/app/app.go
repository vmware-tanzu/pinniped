/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/internal/autoregistration"
	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/internal/downward"
	"github.com/suzerain-io/placeholder-name/pkg/config"
	"github.com/suzerain-io/placeholder-name/pkg/handlers"
)

// shutdownGracePeriod controls how long active connections are allowed to continue at shutdown.
const shutdownGracePeriod = 5 * time.Second

// App is an object that represents the placeholder-name application.
type App struct {
	cmd *cobra.Command

	// CLI flags
	configPath      string
	downwardAPIPath string

	// listen address for healthz serve
	healthAddr string

	// listen address for main serve
	mainAddr string

	// webhook authenticates tokens
	webhook authenticator.Token
}

// New constructs a new App with command line args, stdout and stderr.
func New(args []string, stdout, stderr io.Writer) *App {
	a := &App{
		healthAddr: ":8080",
		mainAddr:   ":443",
	}

	cmd := &cobra.Command{
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load the Kubernetes client configuration (kubeconfig),
			kubeConfig, err := restclient.InClusterConfig()
			if err != nil {
				return fmt.Errorf("could not load in-cluster configuration: %w", err)
			}

			// explicitly use protobuf when talking to built-in kube APIs
			protoKubeConfig := createProtoKubeConfig(kubeConfig)

			// Connect to the core Kubernetes API.
			k8s, err := kubernetes.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			// Connect to the Kubernetes aggregation API.
			aggregation, err := aggregationv1client.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}
			return a.serve(context.Background(), k8s.CoreV1(), aggregation)
		},
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.Flags().StringVarP(
		&a.configPath,
		"config",
		"c",
		"placeholder-name.yaml",
		"path to configuration file",
	)

	cmd.Flags().StringVar(
		&a.downwardAPIPath,
		"downward-api-path",
		"/etc/podinfo",
		"path to Downward API volume mount",
	)

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}

func (a *App) serve(ctx context.Context, k8s corev1client.CoreV1Interface, aggregation aggregationv1client.Interface) error {
	cfg, err := config.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	webhook, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could create webhook client: %w", err)
	}
	a.webhook = webhook

	podinfo, err := downward.Load(a.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}

	ca, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}
	caBundle, err := ca.Bundle()
	if err != nil {
		return fmt.Errorf("could not read CA bundle: %w", err)
	}
	log.Printf("initialized CA bundle:\n%s", string(caBundle))

	cert, err := ca.Issue(
		pkix.Name{CommonName: "Placeholder Server"},
		[]string{"placeholder-serve"},
		24*365*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	// Start an errgroup to manage the lifetimes of the various listener goroutines.
	eg, ctx := errgroup.WithContext(ctx)

	// Dynamically register our v1alpha1 API service.
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "placeholder-name-api"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.IntOrString{IntVal: 443}, //TODO: parse this out of mainAddr
				},
			},
			Selector: podinfo.Labels,
			Type:     corev1.ServiceTypeClusterIP,
		},
	}
	apiService := apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: placeholderv1alpha1.SchemeGroupVersion.Version + "." + placeholderv1alpha1.GroupName,
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:                placeholderv1alpha1.GroupName,
			Version:              placeholderv1alpha1.SchemeGroupVersion.Version,
			CABundle:             caBundle,
			GroupPriorityMinimum: 2500,
			VersionPriority:      10,
		},
	}
	if err := autoregistration.Setup(ctx, autoregistration.SetupOptions{
		CoreV1:             k8s,
		AggregationV1:      aggregation,
		Namespace:          podinfo.Namespace,
		ServiceTemplate:    service,
		APIServiceTemplate: apiService,
	}); err != nil {
		return fmt.Errorf("could not register API service: %w", err)
	}

	// Start healthz listener
	eg.Go(func() error {
		log.Printf("Starting healthz serve on %v", a.healthAddr)
		server := http.Server{
			BaseContext: func(_ net.Listener) context.Context { return ctx },
			Addr:        a.healthAddr,
			Handler:     handlers.New(),
		}
		return runGracefully(ctx, &server, eg, server.ListenAndServe)
	})

	// Start main service listener
	eg.Go(func() error {
		log.Printf("Starting main serve on %v", a.mainAddr)
		server := http.Server{
			BaseContext: func(_ net.Listener) context.Context { return ctx },
			Addr:        a.mainAddr,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
			},
			Handler: http.HandlerFunc(a.exampleHandler),
		}
		return runGracefully(ctx, &server, eg, func() error {
			// Doc for ListenAndServeTLS says we can pass empty strings if we configured
			// keypair for TLS in http.Server.TLSConfig.
			return server.ListenAndServeTLS("", "")
		})
	})

	if err := eg.Wait(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// exampleHandler is a stub to be replaced with our real server logic.
func (a *App) exampleHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	rsp, authenticated, err := a.webhook.AuthenticateToken(ctx, "")
	log.Printf("token response: %+v", rsp)
	log.Printf("token authenticated: %+v", authenticated)
	log.Printf("token err: %+v", err)

	_, _ = w.Write([]byte("hello world"))
}

// runGracefully runs an http.Server with graceful shutdown.
func runGracefully(ctx context.Context, srv *http.Server, eg *errgroup.Group, f func() error) error {
	// Start the listener in a child goroutine.
	eg.Go(f)

	// If/when the context is canceled or times out, initiate shutting down the serve.
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// createProtoKubeConfig returns a copy of the input config with the ContentConfig set to use protobuf.
// do not use this config to communicate with any CRD based APIs.
func createProtoKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	protoKubeConfig := restclient.CopyConfig(kubeConfig)
	const protoThenJSON = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	protoKubeConfig.AcceptContentTypes = protoThenJSON
	protoKubeConfig.ContentType = runtime.ContentTypeProtobuf
	return protoKubeConfig
}
