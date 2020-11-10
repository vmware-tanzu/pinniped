// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/pkg/version"

	loginapi "go.pinniped.dev/generated/1.19/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/registry/credentialrequest"
)

var (
	//nolint: gochecknoglobals
	scheme = runtime.NewScheme()
	//nolint: gochecknoglobals, golint
	Codecs = serializer.NewCodecFactory(scheme)
)

//nolint: gochecknoinits
func init() {
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
}

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type ExtraConfig struct {
	Authenticator                 credentialrequest.TokenCredentialRequestAuthenticator
	Issuer                        credentialrequest.CertIssuer
	StartControllersPostStartHook func(ctx context.Context)
}

type PinnipedServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
	}

	versionInfo := version.Get()
	completedCfg.GenericConfig.Version = &versionInfo

	return CompletedConfig{completedConfig: &completedCfg}
}

// New returns a new instance of AdmissionServer from the given config.
func (c completedConfig) New() (*PinnipedServer, error) {
	genericServer, err := c.GenericConfig.New("pinniped-concierge", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, fmt.Errorf("completion error: %w", err)
	}

	s := &PinnipedServer{
		GenericAPIServer: genericServer,
	}

	gvr := loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests")
	storage := credentialrequest.NewREST(c.ExtraConfig.Authenticator, c.ExtraConfig.Issuer)
	if err := s.GenericAPIServer.InstallAPIGroup(&genericapiserver.APIGroupInfo{
		PrioritizedVersions:          []schema.GroupVersion{gvr.GroupVersion()},
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{gvr.Version: {gvr.Resource: storage}},
		OptionsExternalVersion:       &schema.GroupVersion{Version: "v1"},
		Scheme:                       scheme,
		ParameterCodec:               metav1.ParameterCodec,
		NegotiatedSerializer:         Codecs,
	}); err != nil {
		return nil, fmt.Errorf("could not install API group %s: %w", gvr.String(), err)
	}

	s.GenericAPIServer.AddPostStartHookOrDie("start-controllers",
		func(postStartContext genericapiserver.PostStartHookContext) error {
			plog.Debug("start-controllers post start hook starting")

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				<-postStartContext.StopCh
				cancel()
			}()
			c.ExtraConfig.StartControllersPostStartHook(ctx)

			return nil
		},
	)

	return s, nil
}
