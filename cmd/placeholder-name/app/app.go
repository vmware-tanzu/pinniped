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

	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/pkg/handlers"
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

	// runFunc runs the actual program, after the parsing of flags has been done.
	//
	// It is mostly a field for the sake of testing.
	runFunc func(ctx context.Context, configPath string) error
}

// New constructs a new App with command line args, stdout and stderr.
func New(args []string, stdout, stderr io.Writer) *App {
	a := &App{
		healthAddr: ":8080",
		mainAddr:   ":8443",
	}
	a.runFunc = a.serve

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
		"placeholder-name.yaml",
		"path to configuration file",
	)

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}

func (a *App) serve(ctx context.Context, configPath string) error {
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

	// Start healthz listener
	eg.Go(func() error {
		log.Printf("Starting healthz serve on %v", a.healthAddr)
		server := http.Server{
			BaseContext: func(_ net.Listener) context.Context { return ctx },
			Addr:        a.healthAddr,
			Handler:     handlers.New(),
		}
		return runGracefully(ctx, &server, eg)
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
			Handler: http.HandlerFunc(exampleHandler),
		}
		return runGracefully(ctx, &server, eg)
	})

	if err := eg.Wait(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// exampleHandler is a stub to be replaced with our real server logic.
func exampleHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello world"))
}

// runGracefully runs an http.Server with graceful shutdown.
func runGracefully(ctx context.Context, srv *http.Server, eg *errgroup.Group) error {
	// Start the listener in a child goroutine.
	eg.Go(srv.ListenAndServe)

	// If/when the context is canceled or times out, initiate shutting down the serve.
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
