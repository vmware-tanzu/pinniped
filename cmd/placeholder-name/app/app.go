/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/apiserver"
	"github.com/suzerain-io/placeholder-name/pkg/config"
)

// shutdownGracePeriod controls how long active connections are allowed to continue at shutdown.
const shutdownGracePeriod = 5 * time.Second

// App is an object that represents the placeholder-name application.
type App struct {
	cmd *cobra.Command

	// runFunc runs the actual program, after the parsing of flags has been done.
	//
	// It is mostly a field for the sake of testing.
	runFunc func(ctx context.Context, configPath string) error

	recommendedOptions *genericoptions.RecommendedOptions
}

// This is ignored for now because we turn off etcd storage below, but this is the right prefix in case we turn it back on
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(ctx context.Context, args []string, stdout, stderr io.Writer) *App {
	a := &App{
		recommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
		),
	}
	a.runFunc = a.run
	a.recommendedOptions.Etcd = nil // turn off etcd storage

	var configPath string
	cmd := &cobra.Command{
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runFunc(ctx, configPath)
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

func (a *App) run(ctx context.Context, configPath string) error {
	cfg, err := config.FromPath(configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	webhookTokenAuthenticator, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could create webhook client: %w", err)
	}

	apiServerConfig, err := a.ConfigServer(webhookTokenAuthenticator)
	if err != nil {
		return err
	}

	server, err := apiServerConfig.Complete().New()
	if err != nil {
		return err
	}

	return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

func (a *App) ConfigServer(webhookTokenAuthenticator *webhook.WebhookTokenAuthenticator) (*apiserver.Config, error) {
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
		ExtraConfig: apiserver.ExtraConfig{
			Webhook: webhookTokenAuthenticator,
		},
	}
	return apiServerConfig, nil
}

// drop
