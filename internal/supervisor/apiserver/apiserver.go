// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilversion "k8s.io/apiserver/pkg/util/version"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1alpha1clientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/pversion"
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
	Secrets                            corev1client.SecretInterface
	OIDCClients                        configv1alpha1clientset.OIDCClientInterface
	Namespace                          string
	AuditLogger                        plog.AuditLogger
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
	genericServer, err := c.GenericConfig.New("pinniped-supervisor", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, fmt.Errorf("completion error: %w", err)
	}

	s := &PinnipedServer{
		GenericAPIServer: genericServer,
	}

	var errs []error //nolint:prealloc
	for _, f := range []func() (schema.GroupVersionResource, rest.Storage){
		func() (schema.GroupVersionResource, rest.Storage) {
			clientSecretReqGVR := c.ExtraConfig.ClientSecretSupervisorGroupVersion.WithResource("oidcclientsecretrequests")
			clientSecretReqStorage := clientsecretrequest.NewREST(
				clientSecretReqGVR.GroupResource(),
				c.ExtraConfig.Secrets,
				c.ExtraConfig.OIDCClients,
				c.ExtraConfig.Namespace,
				clientsecretrequest.Cost,
				rand.Reader,
				bcrypt.GenerateFromPassword,
				metav1.Now,
				c.ExtraConfig.AuditLogger,
			)
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
