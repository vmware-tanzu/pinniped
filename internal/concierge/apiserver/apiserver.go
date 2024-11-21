// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilversion "k8s.io/apiserver/pkg/util/version"

	"go.pinniped.dev/internal/clientcertissuer"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/pversion"
	"go.pinniped.dev/internal/registry/credentialrequest"
	"go.pinniped.dev/internal/registry/whoamirequest"
	"go.pinniped.dev/internal/tokenclient"
)

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type ExtraConfig struct {
	Authenticator                 credentialrequest.TokenCredentialRequestAuthenticator
	Issuer                        clientcertissuer.ClientCertIssuer
	BuildControllersPostStartHook controllerinit.RunnerBuilder
	Scheme                        *runtime.Scheme
	NegotiatedSerializer          runtime.NegotiatedSerializer
	LoginConciergeGroupVersion    schema.GroupVersion
	IdentityConciergeGroupVersion schema.GroupVersion
	TokenClient                   *tokenclient.TokenClient
	AuditLogger                   plog.AuditLogger
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
	// Be sure to set this before calling c.GenericConfig.Complete()
	c.GenericConfig.EffectiveVersion = utilversion.NewEffectiveVersion(pversion.Get().String())

	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
	}
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

	var errs []error //nolint:prealloc
	for _, f := range []func() (schema.GroupVersionResource, rest.Storage){
		func() (schema.GroupVersionResource, rest.Storage) {
			tokenCredReqGVR := c.ExtraConfig.LoginConciergeGroupVersion.WithResource("tokencredentialrequests")
			tokenCredStorage := credentialrequest.NewREST(
				c.ExtraConfig.Authenticator,
				c.ExtraConfig.Issuer,
				tokenCredReqGVR.GroupResource(),
				c.ExtraConfig.AuditLogger,
			)
			return tokenCredReqGVR, tokenCredStorage
		},
		func() (schema.GroupVersionResource, rest.Storage) {
			whoAmIReqGVR := c.ExtraConfig.IdentityConciergeGroupVersion.WithResource("whoamirequests")
			whoAmIStorage := whoamirequest.NewREST(whoAmIReqGVR.GroupResource())
			return whoAmIReqGVR, whoAmIStorage
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
	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, fmt.Errorf("could not install API groups: %w", err)
	}

	controllersShutdownWaitGroup := &sync.WaitGroup{}
	controllersCtx, cancelControllerCtx := context.WithCancel(context.Background())

	s.GenericAPIServer.AddPostStartHookOrDie("start-controllers",
		func(_ genericapiserver.PostStartHookContext) error {
			plog.Debug("start-controllers post start hook starting")
			defer plog.Debug("start-controllers post start hook completed")

			runControllers, err := c.ExtraConfig.BuildControllersPostStartHook(controllersCtx)
			if err != nil {
				return fmt.Errorf("cannot create run controller func: %w", err)
			}

			controllersShutdownWaitGroup.Add(1)
			go func() {
				// When this goroutine ends, then also end the WaitGroup, allowing anyone who called Wait() to proceed.
				defer controllersShutdownWaitGroup.Done()

				// Start the controllers and block until their context is cancelled and they have shut down.
				runControllers(controllersCtx)
				plog.Debug("start-controllers post start hook's background goroutine saw runControllers() finish")
			}()

			return nil
		},
	)

	s.GenericAPIServer.AddPostStartHookOrDie("fetch-impersonation-proxy-tokens",
		func(_ genericapiserver.PostStartHookContext) error {
			plog.Debug("fetch-impersonation-proxy-tokens start hook starting")
			defer plog.Debug("fetch-impersonation-proxy-tokens start hook completed")

			controllersShutdownWaitGroup.Add(1)
			go func() {
				defer controllersShutdownWaitGroup.Done()

				// Start the token client
				c.ExtraConfig.TokenClient.Start(controllersCtx)
				plog.Debug("fetch-impersonation-proxy-tokens start hook's background goroutine has finished")
			}()

			return nil
		},
	)

	s.GenericAPIServer.AddPreShutdownHookOrDie("stop-controllers",
		func() error {
			plog.Debug("stop-controllers pre shutdown hook starting")
			defer plog.Debug("stop-controllers pre shutdown hook completed")

			// The generic api server is telling us that it wants to shut down, so tell our controllers that we
			// want them to shut down by cancelling their context.
			cancelControllerCtx()

			// Now wait for the controllers to finish shutting down. By blocking here, we prevent the generic api server's
			// graceful shutdown process from continuing until we are finished shutting down our own controllers.
			controllersShutdownWaitGroup.Wait()

			return nil
		},
	)

	return s, nil
}
