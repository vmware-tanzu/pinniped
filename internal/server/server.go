/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package server is the command line entry point for placeholder-name-server.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"

	"github.com/suzerain-io/placeholder-name/internal/apiserver"
	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/internal/controller"
	"github.com/suzerain-io/placeholder-name/internal/downward"
	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name/kubernetes/1.19/api/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/config"
)

// App is an object that represents the placeholder-name-server application.
type App struct {
	serverCommand *cobra.Command

	// CLI flags
	configPath                 string
	downwardAPIPath            string
	clusterSigningCertFilePath string
	clusterSigningKeyFilePath  string
}

// This is ignored for now because we turn off etcd storage below, but this is
// the right prefix in case we turn it back on.
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(ctx context.Context, args []string, stdout, stderr io.Writer) *App {
	app := &App{}
	app.addServerCommand(ctx, args, stdout, stderr)
	return app
}

// Run the server.
func (app *App) Run() error {
	return app.serverCommand.Execute()
}

// Create the server command and save it into the App.
func (app *App) addServerCommand(ctx context.Context, args []string, stdout, stderr io.Writer) {
	cmd := &cobra.Command{
		Use: `placeholder-name-server`,
		Long: "placeholder-name-server provides a generic API for mapping an external\n" +
			"credential from somewhere to an internal credential to be used for\n" +
			"authenticating to the Kubernetes API.",
		RunE: func(cmd *cobra.Command, args []string) error { return app.runServer(ctx) },
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	addCommandlineFlagsToCommand(cmd, app)

	app.serverCommand = cmd
}

// Define the app's commandline flags.
func addCommandlineFlagsToCommand(cmd *cobra.Command, app *App) {
	cmd.Flags().StringVarP(
		&app.configPath,
		"config",
		"c",
		"placeholder-name.yaml",
		"path to configuration file",
	)

	cmd.Flags().StringVar(
		&app.downwardAPIPath,
		"downward-api-path",
		"/etc/podinfo",
		"path to Downward API volume mount",
	)

	cmd.Flags().StringVar(
		&app.clusterSigningCertFilePath,
		"cluster-signing-cert-file",
		"",
		"path to cluster signing certificate",
	)

	cmd.Flags().StringVar(
		&app.clusterSigningKeyFilePath,
		"cluster-signing-key-file",
		"",
		"path to cluster signing private key",
	)
}

// Boot the aggregated API server, which will in turn boot the controllers.
func (app *App) runServer(ctx context.Context) error {
	// Read the server config file.
	cfg, err := config.FromPath(app.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	// Load the Kubernetes cluster signing CA.
	k8sClusterCA, err := certauthority.Load(app.clusterSigningCertFilePath, app.clusterSigningKeyFilePath)
	if err != nil {
		return fmt.Errorf("could not load cluster signing CA: %w", err)
	}

	// Create a WebhookTokenAuthenticator.
	webhookTokenAuthenticator, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could not create webhook client: %w", err)
	}

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(app.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}
	serverInstallationNamespace := podInfo.Namespace

	// Create a CA.
	aggregatedAPIServerCA, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}

	// This string must match the name of the Service declared in the deployment yaml.
	const serviceName = "placeholder-name-api"
	// Using the CA from above, create a TLS server cert for the aggregated API server to use.
	aggregatedAPIServerTLSCert, err := aggregatedAPIServerCA.Issue(
		pkix.Name{CommonName: serviceName + "." + serverInstallationNamespace + ".svc"},
		[]string{},
		24*365*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	// Prepare to start the controllers, but defer actually starting them until the
	// post start hook of the aggregated API server.
	startControllersFunc, err := controller.PrepareControllers(
		ctx,
		aggregatedAPIServerCA.Bundle(),
		serverInstallationNamespace,
		cfg.DiscoveryConfig.URL,
	)
	if err != nil {
		return fmt.Errorf("could not prepare controllers: %w", err)
	}

	// Get the aggregated API server config.
	aggregatedAPIServerConfig, err := getAggregatedAPIServerConfig(
		aggregatedAPIServerTLSCert,
		webhookTokenAuthenticator,
		k8sClusterCA,
		startControllersFunc,
	)
	if err != nil {
		return fmt.Errorf("could not configure aggregated API server: %w", err)
	}

	// Complete the aggregated API server config and make a server instance.
	server, err := aggregatedAPIServerConfig.Complete().New()
	if err != nil {
		return fmt.Errorf("could not create aggregated API server: %w", err)
	}

	// Run the server. Its post-start hook will start the controllers.
	return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

// Create a configuration for the aggregated API server.
func getAggregatedAPIServerConfig(
	cert *tls.Certificate,
	webhookTokenAuthenticator *webhook.WebhookTokenAuthenticator,
	ca *certauthority.CA,
	startControllersPostStartHook func(context.Context),
) (*apiserver.Config, error) {
	provider, err := createStaticCertKeyProvider(cert)
	if err != nil {
		return nil, fmt.Errorf("could not create static cert key provider: %w", err)
	}

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
		// TODO we should check to see if all the other default settings are acceptable for us
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = provider

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			Webhook:                       webhookTokenAuthenticator,
			Issuer:                        ca,
			StartControllersPostStartHook: startControllersPostStartHook,
		},
	}
	return apiServerConfig, nil
}

func createStaticCertKeyProvider(cert *tls.Certificate) (dynamiccertificates.CertKeyContentProvider, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDER,
	})

	certChainPEM := make([]byte, 0)
	for _, certFromChain := range cert.Certificate {
		certPEMBytes := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   certFromChain,
		})
		certChainPEM = append(certChainPEM, certPEMBytes...)
	}

	return dynamiccertificates.NewStaticCertKeyContent("some-name???", certChainPEM, privateKeyPEM)
}
