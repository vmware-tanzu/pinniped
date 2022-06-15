// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/pkg/version"

	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/registry/clientsecretrequest"
)

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type ExtraConfig struct {
	BuildControllersPostStartHook      controllerinit.RunnerBuilder
	Scheme                             *runtime.Scheme
	NegotiatedSerializer               runtime.NegotiatedSerializer
	ClientSecretSupervisorGroupVersion schema.GroupVersion
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
	genericServer, err := c.GenericConfig.New("pinniped-supervisor", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, fmt.Errorf("completion error: %w", err)
	}

	s := &PinnipedServer{
		GenericAPIServer: genericServer,
	}

	var errs []error //nolint: prealloc
	for _, f := range []func() (schema.GroupVersionResource, rest.Storage){
		func() (schema.GroupVersionResource, rest.Storage) {
			clientSecretReqGVR := c.ExtraConfig.ClientSecretSupervisorGroupVersion.WithResource("oidcclientsecretrequests")
			clientSecretReqStorage := clientsecretrequest.NewREST(clientSecretReqGVR.GroupResource())
			return clientSecretReqGVR, clientSecretReqStorage
		},
	} {
		gvr, storage := f()
		errs = append(errs,
			s.GenericAPIServer.InstallAPIGroup(
				&genericapiserver.APIGroupInfo{
					PrioritizedVersions:          []schema.GroupVersion{gvr.GroupVersion()},
					VersionedResourcesStorageMap: map[string]map[string]rest.Storage{gvr.Version: {gvr.Resource: storage}},
					OptionsExternalVersion:       &schema.GroupVersion{Version: "v1"},
					Scheme:                       c.ExtraConfig.Scheme,
					ParameterCodec:               metav1.ParameterCodec,
					NegotiatedSerializer:         c.ExtraConfig.NegotiatedSerializer,
				},
			),
		)
	}
	if err := errors.NewAggregate(errs); err != nil {
		return nil, fmt.Errorf("could not install API groups: %w", err)
	}

	shutdown := &sync.WaitGroup{}
	s.GenericAPIServer.AddPostStartHookOrDie("start-controllers",
		func(postStartContext genericapiserver.PostStartHookContext) error {
			plog.Debug("start-controllers post start hook starting")

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer cancel()

				<-postStartContext.StopCh
			}()

			runControllers, err := c.ExtraConfig.BuildControllersPostStartHook(ctx)
			if err != nil {
				return fmt.Errorf("cannot create run controller func: %w", err)
			}

			shutdown.Add(1)
			go func() {
				defer shutdown.Done()

				runControllers(ctx)
			}()

			return nil
		},
	)
	s.GenericAPIServer.AddPreShutdownHookOrDie("stop-controllers",
		func() error {
			plog.Debug("stop-controllers pre shutdown hook starting")
			defer plog.Debug("stop-controllers pre shutdown hook completed")

			shutdown.Wait()

			return nil
		},
	)

	return s, nil
}
