// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package server is the command line entry point for pinniped-concierge.
package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/certauthority/dynamiccertauthority"
	"go.pinniped.dev/internal/concierge/apiserver"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/controllermanager"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/issuer"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/registry/credentialrequest"
)

// App is an object that represents the pinniped-concierge application.
type App struct {
	cmd *cobra.Command

	// CLI flags
	configPath      string
	downwardAPIPath string
}

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
		Use: "pinniped-concierge",
		Long: here.Doc(`
			pinniped-concierge provides a generic API for mapping an external
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
	cfg, err := concierge.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	// Discover in which namespace we are installed.
	podInfo, err := downward.Load(a.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}

	// Initialize the cache of active authenticators.
	authenticators := authncache.New()

	// This cert provider will provide certs to the API server and will
	// be mutated by a controller to keep the certs up to date with what
	// is stored in a k8s Secret. Therefore it also effectively acting as
	// an in-memory cache of what is stored in the k8s Secret, helping to
	// keep incoming requests fast.
	dynamicServingCertProvider := dynamiccert.NewServingCert("concierge-serving-cert")

	// This cert provider will be used to provide the Kube signing key to the
	// cert issuer used to issue certs to Pinniped clients wishing to login.
	dynamicSigningCertProvider := dynamiccert.NewCA("concierge-kube-signing-cert")

	// This cert provider will be used to provide the impersonation proxy signing key to the
	// cert issuer used to issue certs to Pinniped clients wishing to login.
	impersonationProxySigningCertProvider := dynamiccert.NewCA("impersonation-proxy-signing-cert")

	// Get the "real" name of the login concierge API group (i.e., the API group name with the
	// injected suffix).
	scheme, loginGV, identityGV := conciergescheme.New(*cfg.APIGroupSuffix)

	// Prepare to start the controllers, but defer actually starting them until the
	// post start hook of the aggregated API server.
	buildControllers, err := controllermanager.PrepareControllers(
		&controllermanager.Config{
			ServerInstallationInfo:           podInfo,
			APIGroupSuffix:                   *cfg.APIGroupSuffix,
			NamesConfig:                      &cfg.NamesConfig,
			Labels:                           cfg.Labels,
			KubeCertAgentConfig:              &cfg.KubeCertAgentConfig,
			DiscoveryURLOverride:             cfg.DiscoveryInfo.URL,
			DynamicServingCertProvider:       dynamicServingCertProvider,
			DynamicSigningCertProvider:       dynamicSigningCertProvider,
			ImpersonationSigningCertProvider: impersonationProxySigningCertProvider,
			ServingCertDuration:              time.Duration(*cfg.APIConfig.ServingCertificateConfig.DurationSeconds) * time.Second,
			ServingCertRenewBefore:           time.Duration(*cfg.APIConfig.ServingCertificateConfig.RenewBeforeSeconds) * time.Second,
			AuthenticatorCache:               authenticators,
			// This port should be safe to cast because the config reader already validated it.
			ImpersonationProxyServerPort: int(*cfg.ImpersonationProxyServerPort),
		},
	)
	if err != nil {
		return fmt.Errorf("could not prepare controllers: %w", err)
	}

	certIssuer := issuer.ClientCertIssuers{
		dynamiccertauthority.New(dynamicSigningCertProvider),            // attempt to use the real Kube CA if possible
		dynamiccertauthority.New(impersonationProxySigningCertProvider), // fallback to our internal CA if we need to
	}

	// Make a kube client without leader election to allow the rest endpoints to use it selectively
	// only where it makes sense. This could use the deploymentRef middleware, but we don't need it yet.
	clientWithoutLeaderElection, err := kubeclient.New()
	if err != nil {
		return fmt.Errorf("could not create clientWithoutLeaderElection for the rest handlers: %w", err)
	}

	// Get the aggregated API server config.
	aggregatedAPIServerConfig, err := getAggregatedAPIServerConfig(
		clientWithoutLeaderElection.Kubernetes,
		dynamicServingCertProvider,
		authenticators,
		certIssuer,
		buildControllers,
		*cfg.APIGroupSuffix,
		*cfg.AggregatedAPIServerPort,
		scheme,
		loginGV,
		identityGV,
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
	kubeClientWithoutLeaderElection kubernetes.Interface,
	dynamicCertProvider dynamiccert.Private,
	authenticator credentialrequest.TokenCredentialRequestAuthenticator,
	issuer issuer.ClientCertIssuer,
	buildControllers controllerinit.RunnerBuilder,
	apiGroupSuffix string,
	aggregatedAPIServerPort int64,
	scheme *runtime.Scheme,
	loginConciergeGroupVersion, identityConciergeGroupVersion schema.GroupVersion,
) (*apiserver.Config, error) {
	codecs := serializer.NewCodecFactory(scheme)

	// this is unused for now but it is a safe value that we could use in the future
	defaultEtcdPathPrefix := fmt.Sprintf("/pinniped-concierge-registry/%s", apiGroupSuffix)

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		codecs.LegacyCodec(loginConciergeGroupVersion, identityConciergeGroupVersion),
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider

	// This port is configurable. It should be safe to cast because the config reader already validated it.
	recommendedOptions.SecureServing.BindPort = int(aggregatedAPIServerPort)

	// secure TLS for connections coming from and going to the Kube API server
	// this is best effort because not all options provide the right hooks to override TLS config
	// since our only client is the Kube API server, this uses the most secure TLS config
	if err := ptls.SecureRecommendedOptions(recommendedOptions, kubeclient.Secure); err != nil {
		return nil, fmt.Errorf("failed to secure recommended options: %w", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(codecs)
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
		return nil, fmt.Errorf("failed to apply recommended options: %w", err)
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			Authenticator:                   authenticator,
			Issuer:                          issuer,
			BuildControllersPostStartHook:   buildControllers,
			Scheme:                          scheme,
			NegotiatedSerializer:            codecs,
			LoginConciergeGroupVersion:      loginConciergeGroupVersion,
			IdentityConciergeGroupVersion:   identityConciergeGroupVersion,
			KubeClientWithoutLeaderElection: kubeClientWithoutLeaderElection,
		},
	}
	return apiServerConfig, nil
}

func main() error { // return an error instead of klog.Fatal to allow defer statements to run
	logs.InitLogs()
	defer logs.FlushLogs()

	// Dump out the time since compile (mostly useful for benchmarking our local development cycle latency).
	var timeSinceCompile time.Duration
	if buildDate, err := time.Parse(time.RFC3339, version.Get().BuildDate); err == nil {
		timeSinceCompile = time.Since(buildDate).Round(time.Second)
	}
	klog.Infof("Running %s at %#v (%s since build)", rest.DefaultKubernetesUserAgent(), version.Get(), timeSinceCompile)

	ctx := genericapiserver.SetupSignalContext()

	return New(ctx, os.Args[1:], os.Stdout, os.Stderr).Run()
}

func Main() {
	if err := main(); err != nil {
		klog.Fatal(err)
	}
}
