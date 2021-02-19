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

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
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
	scheme, loginConciergeGroupVersion, identityConciergeGroupVersion := getAggregatedAPIServerScheme(apiGroupSuffix)
	codecs := serializer.NewCodecFactory(scheme)

	// this is unused for now but it is a safe value that we could use in the future
	defaultEtcdPathPrefix := fmt.Sprintf("/pinniped-concierge-registry/%s", apiGroupSuffix)

	recommendedOptions := genericoptions.NewRecommendedOptions(
		defaultEtcdPathPrefix,
		codecs.LegacyCodec(loginConciergeGroupVersion, identityConciergeGroupVersion),
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
			LoginConciergeGroupVersion:    loginConciergeGroupVersion,
			IdentityConciergeGroupVersion: identityConciergeGroupVersion,
		},
	}
	return apiServerConfig, nil
}

func getAggregatedAPIServerScheme(apiGroupSuffix string) (_ *runtime.Scheme, login, identity schema.GroupVersion) {
	// standard set up of the server side scheme
	scheme := runtime.NewScheme()

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)

	// nothing fancy is required if using the standard group suffix
	if apiGroupSuffix == groupsuffix.PinnipedDefaultSuffix {
		schemeBuilder := runtime.NewSchemeBuilder(
			loginv1alpha1.AddToScheme,
			loginapi.AddToScheme,
			identityv1alpha1.AddToScheme,
			identityapi.AddToScheme,
		)
		utilruntime.Must(schemeBuilder.AddToScheme(scheme))
		return scheme, loginv1alpha1.SchemeGroupVersion, identityv1alpha1.SchemeGroupVersion
	}

	loginConciergeGroupData, identityConciergeGroupData := groupsuffix.ConciergeAggregatedGroups(apiGroupSuffix)

	addToSchemeAtNewGroup(scheme, loginv1alpha1.GroupName, loginConciergeGroupData.Group, loginv1alpha1.AddToScheme, loginapi.AddToScheme)
	addToSchemeAtNewGroup(scheme, identityv1alpha1.GroupName, identityConciergeGroupData.Group, identityv1alpha1.AddToScheme, identityapi.AddToScheme)

	// manually register conversions and defaulting into the correct scheme since we cannot directly call AddToScheme
	schemeBuilder := runtime.NewSchemeBuilder(
		loginv1alpha1.RegisterConversions,
		loginv1alpha1.RegisterDefaults,
		identityv1alpha1.RegisterConversions,
		identityv1alpha1.RegisterDefaults,
	)
	utilruntime.Must(schemeBuilder.AddToScheme(scheme))

	// we do not want to return errors from the scheme and instead would prefer to defer
	// to the REST storage layer for consistency.  The simplest way to do this is to force
	// a cache miss from the authenticator cache.  Kube API groups are validated via the
	// IsDNS1123Subdomain func thus we can easily create a group that is guaranteed never
	// to be in the authenticator cache.  Add a timestamp just to be extra sure.
	const authenticatorCacheMissPrefix = "_INVALID_API_GROUP_"
	authenticatorCacheMiss := authenticatorCacheMissPrefix + time.Now().UTC().String()

	// we do not have any defaulting functions for *loginv1alpha1.TokenCredentialRequest
	// today, but we may have some in the future.  Calling AddTypeDefaultingFunc overwrites
	// any previously registered defaulting function.  Thus to make sure that we catch
	// a situation where we add a defaulting func, we attempt to call it here with a nil
	// *loginv1alpha1.TokenCredentialRequest.  This will do nothing when there is no
	// defaulting func registered, but it will almost certainly panic if one is added.
	scheme.Default((*loginv1alpha1.TokenCredentialRequest)(nil))

	// on incoming requests, restore the authenticator API group to the standard group
	// note that we are responsible for duplicating this logic for every external API version
	scheme.AddTypeDefaultingFunc(&loginv1alpha1.TokenCredentialRequest{}, func(obj interface{}) {
		credentialRequest := obj.(*loginv1alpha1.TokenCredentialRequest)

		if credentialRequest.Spec.Authenticator.APIGroup == nil {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, nil group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		restoredGroup, ok := groupsuffix.Unreplace(*credentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
		if !ok {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, wrong group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		credentialRequest.Spec.Authenticator.APIGroup = &restoredGroup
	})

	return scheme, schema.GroupVersion(loginConciergeGroupData), schema.GroupVersion(identityConciergeGroupData)
}

func addToSchemeAtNewGroup(scheme *runtime.Scheme, oldGroup, newGroup string, funcs ...func(*runtime.Scheme) error) {
	// we need a temporary place to register our types to avoid double registering them
	tmpScheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(funcs...)
	utilruntime.Must(schemeBuilder.AddToScheme(tmpScheme))

	for gvk := range tmpScheme.AllKnownTypes() {
		if gvk.GroupVersion() == metav1.Unversioned {
			continue // metav1.AddToGroupVersion registers types outside of our aggregated API group that we need to ignore
		}

		if gvk.Group != oldGroup {
			panic(fmt.Errorf("tmp scheme has type not in the old aggregated API group %s: %s", oldGroup, gvk)) // programmer error
		}

		obj, err := tmpScheme.New(gvk)
		if err != nil {
			panic(err) // programmer error, scheme internal code is broken
		}
		newGVK := schema.GroupVersionKind{
			Group:   newGroup,
			Version: gvk.Version,
			Kind:    gvk.Kind,
		}

		// register the existing type but with the new group in the correct scheme
		scheme.AddKnownTypeWithName(newGVK, obj)
	}
}
