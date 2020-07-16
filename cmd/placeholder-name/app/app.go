/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/apiserver"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/pkg/config"
)

// shutdownGracePeriod controls how long active connections are allowed to continue at shutdown.
const shutdownGracePeriod = 5 * time.Second

// App is an object that represents the placeholder-name application.
type App struct {
	cmd *cobra.Command

	// listen address for healthz serve
	healthAddr string

	// listen address for main serve
	mainAddr string

	// webhook authenticates tokens
	webhook authenticator.Token

	// runFunc runs the actual program, after the parsing of flags has been done.
	//
	// It is mostly a field for the sake of testing.
	runFunc func(ctx context.Context, configPath string) error

	recommendedOptions *genericoptions.RecommendedOptions

	stopCh <-chan struct{}
}

// TODO this is ignored for now because we nil out etcd options
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(args []string, stdout, stderr io.Writer, stopCh <-chan struct{}) *App {
	a := &App{
		healthAddr: ":8080",
		mainAddr:   ":8443",
		stopCh:     stopCh,
		recommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
		),
	}
	a.runFunc = a.serve
	a.recommendedOptions.Etcd = nil
	a.recommendedOptions.Admission = nil

	var configPath string
	cmd := &cobra.Command{
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runFunc(context.Background(), configPath)
		},
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.Flags().StringVarP(
		&configPath,
		"config",
		"c",
		"/etc/config/placeholder-name.yaml",
		"path to configuration file",
	)

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}

func (a *App) serve(ctx context.Context, configPath string) error {
	cfg, err := config.FromPath(configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	webhook, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could create webhook client: %w", err)
	}
	a.webhook = webhook

	ca, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}
	caBundle, err := ca.Bundle()
	if err != nil {
		return fmt.Errorf("could not read CA bundle: %w", err)
	}
	log.Printf("initialized CA bundle:\n%s", string(caBundle))

	//cert, err := ca.Issue(
	//	pkix.Name{CommonName: "Placeholder Server"},
	//	[]string{"placeholder-serve"},
	//	24*365*time.Hour,
	//)
	//if err != nil {
	//	return fmt.Errorf("could not issue serving certificate: %w", err)
	//}
	//
	//// Start an errgroup to manage the lifetimes of the various listener goroutines.
	//eg, ctx := errgroup.WithContext(ctx)
	//
	//// Start healthz listener
	//eg.Go(func() error {
	//	log.Printf("Starting healthz serve on %v", a.healthAddr)
	//	server := http.Server{
	//		BaseContext: func(_ net.Listener) context.Context { return ctx },
	//		Addr:        a.healthAddr,
	//		Handler:     handlers.New(),
	//	}
	//	return runGracefully(ctx, &server, eg, server.ListenAndServe)
	//})
	//
	//// Start main service listener
	//eg.Go(func() error {
	//	log.Printf("Starting main serve on %v", a.mainAddr)
	//	server := http.Server{
	//		BaseContext: func(_ net.Listener) context.Context { return ctx },
	//		Addr:        a.mainAddr,
	//		TLSConfig: &tls.Config{
	//			MinVersion:   tls.VersionTLS12,
	//			Certificates: []tls.Certificate{*cert},
	//		},
	//		Handler: http.HandlerFunc(a.exampleHandler),
	//	}
	//	return runGracefully(ctx, &server, eg, func() error {
	//		// Doc for ListenAndServeTLS says we can pass empty strings if we configured
	//		// keypair for TLS in http.Server.TLSConfig.
	//		return server.ListenAndServeTLS("", "")
	//	})
	//})
	//
	//if err := eg.Wait(); !errors.Is(err, http.ErrServerClosed) {
	//	return err
	//}

	apiServerConfig, err := a.ConfigServer()
	if err != nil {
		return err
	}

	server, err := apiServerConfig.Complete().New()
	if err != nil {
		return err
	}

	return server.GenericAPIServer.PrepareRun().Run(a.stopCh)
}

func (a *App) ConfigServer() (*apiserver.Config, error) {
	// TODO have a "real" external address. Get this from some kind of config input or preferably some environment variable.
	if err := a.recommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("placeholder-name.placeholder.svc", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %w", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := a.recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig:   apiserver.ExtraConfig{
			// TODO do we need any ExtraConfig?
		},
	}
	return apiServerConfig, nil
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
