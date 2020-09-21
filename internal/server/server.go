// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package server is the command line entry point for pinniped-server.
package server

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/1.19/apis/login/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/apiserver"
	"go.pinniped.dev/internal/certauthority/kubecertauthority"
	"go.pinniped.dev/internal/controller/identityprovider/idpcache"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllermanager"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/provider"
	"go.pinniped.dev/internal/registry/credentialrequest"
	"go.pinniped.dev/pkg/config"
)

// App is an object that represents the pinniped-server application.
type App struct {
	cmd *cobra.Command

	// CLI flags
	configPath      string
	downwardAPIPath string
}

// This is ignored for now because we turn off etcd storage below, but this is
// the right prefix in case we turn it back on.
const defaultEtcdPathPrefix = "/registry/" + loginv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(ctx context.Context, args []string, stdout, stderr io.Writer) *App {
	app := &App{}
	app.addServerCommand(ctx, args, stdout, stderr)
	return app
}

// Run the server.
func (a *App) Run() error {
	return a.cmd.Execute()
}

// Create the server command and save it into the App.
func (a *App) addServerCommand(ctx context.Context, args []string, stdout, stderr io.Writer) {
	cmd := &cobra.Command{
		Use: "pinniped-server",
		Long: here.Doc(`
			pinniped-server provides a generic API for mapping an external
			credential from somewhere to an internal credential to be used for
			authenticating to the Kubernetes API.`),
		RunE: func(cmd *cobra.Command, args []string) error { return a.runServer(ctx) },
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	addCommandlineFlagsToCommand(cmd, a)

	a.cmd = cmd
}

// Define the app's commandline flags.
func addCommandlineFlagsToCommand(cmd *cobra.Command, app *App) {
	cmd.Flags().StringVarP(
		&app.configPath,
		"config",
		"c",
		"pinniped.yaml",
		"path to configuration file",
	)

	cmd.Flags().StringVar(
		&app.downwardAPIPath,
		"downward-api-path",
		"/etc/podinfo",
		"path to Downward API volume mount",
	)
}

// Boot the aggregated API server, which will in turn boot the controllers.
func (a *App) runServer(ctx context.Context) error {
	// Read the server config file.
	cfg, err := config.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(a.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}
	serverInstallationNamespace := podInfo.Namespace

	// Load the Kubernetes cluster signing CA.
	k8sClusterCA, shutdownCA, err := getClusterCASigner(ctx, serverInstallationNamespace, cfg.NamesConfig.CredentialIssuerConfig)
	if err != nil {
		return err
	}
	defer shutdownCA()

	// Initialize the cache of active identity providers.
	idpCache := idpcache.New()

	// This cert provider will provide certs to the API server and will
	// be mutated by a controller to keep the certs up to date with what
	// is stored in a k8s Secret. Therefore it also effectively acting as
	// an in-memory cache of what is stored in the k8s Secret, helping to
	// keep incoming requests fast.
	dynamicCertProvider := provider.NewDynamicTLSServingCertProvider()

	// Prepare to start the controllers, but defer actually starting them until the
	// post start hook of the aggregated API server.
	startControllersFunc, err := controllermanager.PrepareControllers(
		serverInstallationNamespace,
		cfg.NamesConfig,
		cfg.DiscoveryInfo.URL,
		dynamicCertProvider,
		time.Duration(*cfg.APIConfig.ServingCertificateConfig.DurationSeconds)*time.Second,
		time.Duration(*cfg.APIConfig.ServingCertificateConfig.RenewBeforeSeconds)*time.Second,
		idpCache,
	)
	if err != nil {
		return fmt.Errorf("could not prepare controllers: %w", err)
	}

	// Get the aggregated API server config.
	aggregatedAPIServerConfig, err := getAggregatedAPIServerConfig(
		dynamicCertProvider,
		idpCache,
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

func getClusterCASigner(
	ctx context.Context, serverInstallationNamespace string,
	credentialIssuerConfigResourceName string,
) (credentialrequest.CertIssuer, kubecertauthority.ShutdownFunc, error) {
	// Load the Kubernetes client configuration.
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// Connect to the core Kubernetes API.
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the pinniped API.
	pinnipedClient, err := pinnipedclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	// Make a clock tick that triggers a periodic refresh.
	ticker := time.NewTicker(5 * time.Minute)

	// Make a CA which uses the Kubernetes cluster API server's signing certs.
	k8sClusterCA, shutdownCA := kubecertauthority.New(
		kubeClient,
		kubecertauthority.NewPodCommandExecutor(kubeConfig, kubeClient),
		ticker.C,
		func() { // success callback
			err = issuerconfig.CreateOrUpdateCredentialIssuerConfig(
				ctx,
				serverInstallationNamespace,
				credentialIssuerConfigResourceName,
				pinnipedClient,
				func(configToUpdate *configv1alpha1.CredentialIssuerConfig) {
					configToUpdate.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{
						{
							Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
							Status:         configv1alpha1.SuccessStrategyStatus,
							Reason:         configv1alpha1.FetchedKeyStrategyReason,
							Message:        "Key was fetched successfully",
							LastUpdateTime: metav1.Now(),
						},
					}
				},
			)
			if err != nil {
				klog.Errorf("error performing create or update on CredentialIssuerConfig to add strategy success: %s", err.Error())
			}
		},
		func(err error) { // error callback
			if updateErr := issuerconfig.CreateOrUpdateCredentialIssuerConfig(
				ctx,
				serverInstallationNamespace,
				credentialIssuerConfigResourceName,
				pinnipedClient,
				func(configToUpdate *configv1alpha1.CredentialIssuerConfig) {
					configToUpdate.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{
						{
							Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
							Status:         configv1alpha1.ErrorStrategyStatus,
							Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
							Message:        err.Error(),
							LastUpdateTime: metav1.Now(),
						},
					}
				},
			); updateErr != nil {
				klog.Errorf("error performing create or update on CredentialIssuerConfig to add strategy error: %s", updateErr.Error())
			}
		},
	)

	return k8sClusterCA, func() { shutdownCA(); ticker.Stop() }, nil
}

// Create a configuration for the aggregated API server.
func getAggregatedAPIServerConfig(
	dynamicCertProvider provider.DynamicTLSServingCertProvider,
	authenticator credentialrequest.TokenCredentialRequestAuthenticator,
	issuer credentialrequest.CertIssuer,
	startControllersPostStartHook func(context.Context),
) (*apiserver.Config, error) {
	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		apiserver.Codecs.LegacyCodec(loginv1alpha1.SchemeGroupVersion),
		// TODO we should check to see if all the other default settings are acceptable for us
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	// Note that among other things, this ApplyTo() function copies
	// `recommendedOptions.SecureServing.ServerCert.GeneratedCert` into
	// `serverConfig.SecureServing.Cert` thus making `dynamicCertProvider`
	// the cert provider for the running server. The provider will be called
	// by the API machinery periodically. When the provider returns nil certs,
	// the API server will return "the server is currently unable to
	// handle the request" error responses for all incoming requests.
	// If the provider later starts returning certs, then the API server
	// will use them to handle the incoming requests successfully.
	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			Authenticator:                 authenticator,
			Issuer:                        issuer,
			StartControllersPostStartHook: startControllersPostStartHook,
		},
	}
	return apiServerConfig, nil
}
