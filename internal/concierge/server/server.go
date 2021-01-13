// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package server is the command line entry point for pinniped-concierge.
package server

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	loginapi "go.pinniped.dev/generated/1.20/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/certauthority/dynamiccertauthority"
	"go.pinniped.dev/internal/concierge/apiserver"
	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllermanager"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
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

	plog.RemoveKlogGlobalFlags()
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
	dynamicServingCertProvider := dynamiccert.New()

	// This cert provider will be used to provide a signing key to the
	// cert issuer used to issue certs to Pinniped clients wishing to login.
	dynamicSigningCertProvider := dynamiccert.New()

	// Prepare to start the controllers, but defer actually starting them until the
	// post start hook of the aggregated API server.
	startControllersFunc, err := controllermanager.PrepareControllers(
		&controllermanager.Config{
			ServerInstallationInfo:     podInfo,
			APIGroupSuffix:             *cfg.APIGroupSuffix,
			NamesConfig:                &cfg.NamesConfig,
			Labels:                     cfg.Labels,
			KubeCertAgentConfig:        &cfg.KubeCertAgentConfig,
			DiscoveryURLOverride:       cfg.DiscoveryInfo.URL,
			DynamicServingCertProvider: dynamicServingCertProvider,
			DynamicSigningCertProvider: dynamicSigningCertProvider,
			ServingCertDuration:        time.Duration(*cfg.APIConfig.ServingCertificateConfig.DurationSeconds) * time.Second,
			ServingCertRenewBefore:     time.Duration(*cfg.APIConfig.ServingCertificateConfig.RenewBeforeSeconds) * time.Second,
			AuthenticatorCache:         authenticators,
		},
	)
	if err != nil {
		return fmt.Errorf("could not prepare controllers: %w", err)
	}

	// Get the aggregated API server config.
	aggregatedAPIServerConfig, err := getAggregatedAPIServerConfig(
		dynamicServingCertProvider,
		authenticators,
		dynamiccertauthority.New(dynamicSigningCertProvider),
		startControllersFunc,
		*cfg.APIGroupSuffix,
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
	dynamicCertProvider dynamiccert.Provider,
	authenticator credentialrequest.TokenCredentialRequestAuthenticator,
	issuer credentialrequest.CertIssuer,
	startControllersPostStartHook func(context.Context),
	apiGroupSuffix string,
) (*apiserver.Config, error) {
	apiGroup, ok := groupsuffix.Replace(loginv1alpha1.GroupName, apiGroupSuffix)
	if !ok {
		return nil, fmt.Errorf("cannot make api group from %s/%s", loginv1alpha1.GroupName, apiGroupSuffix)
	}

	// standard set up of the server side scheme
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)

	utilruntime.Must(loginv1alpha1.AddToScheme(scheme))
	utilruntime.Must(loginapi.AddToScheme(scheme))

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)

	// use closure to avoid mutating scheme during iteration
	var addPinnipedTypeToAPIGroup []func() //nolint: prealloc  // expected slice size is unknown
	for gvk := range scheme.AllKnownTypes() {
		gvk := gvk

		if apiGroup == loginv1alpha1.GroupName {
			break // bail out early if using the standard group
		}

		if gvk.Group != loginv1alpha1.GroupName {
			continue // ignore types that are not in the aggregated API group
		}

		// re-register the existing type but with the new group
		f := func() {
			obj, err := scheme.New(gvk)
			if err != nil {
				panic(err) // programmer error, scheme internal code is broken
			}
			newGVK := schema.GroupVersionKind{
				Group:   apiGroup,
				Version: gvk.Version,
				Kind:    gvk.Kind,
			}
			scheme.AddKnownTypeWithName(newGVK, obj)
		}

		addPinnipedTypeToAPIGroup = append(addPinnipedTypeToAPIGroup, f)
	}

	// run the closures to mutate the scheme to understand the types at the new group
	for _, f := range addPinnipedTypeToAPIGroup {
		f()
	}

	defaultEtcdPathPrefix := fmt.Sprintf("/registry/%s", apiGroup)
	groupVersion := schema.GroupVersion{
		Group:   apiGroup,
		Version: loginv1alpha1.SchemeGroupVersion.Version,
	}

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		codecs.LegacyCodec(groupVersion),
	)
	recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider
	recommendedOptions.SecureServing.BindPort = 8443 // Don't run on default 443 because that requires root

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
		return nil, err
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			Authenticator:                 authenticator,
			Issuer:                        issuer,
			StartControllersPostStartHook: startControllersPostStartHook,
			Scheme:                        scheme,
			NegotiatedSerializer:          codecs,
			GroupVersion:                  groupVersion,
		},
	}
	return apiServerConfig, nil
}
