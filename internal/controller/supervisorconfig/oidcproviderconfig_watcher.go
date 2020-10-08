// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"net/url"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	configinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
)

// ProvidersSetter can be notified of all known valid providers with its SetIssuer function.
// If there are no longer any valid issuers, then it can be called with no arguments.
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type ProvidersSetter interface {
	SetProviders(oidcProviders ...*provider.OIDCProvider)
}

type oidcProviderConfigWatcherController struct {
	providerSetter ProvidersSetter
	opcInformer    configinformers.OIDCProviderConfigInformer
}

// NewOIDCProviderConfigWatcherController creates a controllerlib.Controller that watches
// OIDCProviderConfig objects and notifies a callback object of the collection of provider configs.
func NewOIDCProviderConfigWatcherController(
	issuerObserver ProvidersSetter,
	opcInformer configinformers.OIDCProviderConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "OIDCProviderConfigWatcherController",
			Syncer: &oidcProviderConfigWatcherController{
				providerSetter: issuerObserver,
				opcInformer:    opcInformer,
			},
		},
		withInformer(
			opcInformer,
			pinnipedcontroller.NoOpFilter(),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *oidcProviderConfigWatcherController) Sync(ctx controllerlib.Context) error {
	all, err := c.opcInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}

	oidcProviders := make([]*provider.OIDCProvider, 0)
	for _, opc := range all {
		issuerURL, err := url.Parse(opc.Spec.Issuer)
		if err != nil {
			klog.InfoS(
				"OIDCProviderConfigWatcherController Sync failed to parse issuer",
				"err",
				err,
			)
			continue
		}
		oidcProvider := &provider.OIDCProvider{Issuer: issuerURL}
		err = oidcProvider.Validate()
		if err != nil {
			klog.InfoS(
				"OIDCProviderConfigWatcherController Sync could failed to validate OIDCProviderConfig",
				"err",
				err,
			)
			continue
		}
		oidcProviders = append(oidcProviders, oidcProvider)
		klog.InfoS(
			"OIDCProviderConfigWatcherController Sync accepted OIDCProviderConfig",
			"issuer",
			issuerURL,
		)
	}

	c.providerSetter.SetProviders(oidcProviders...)
	return nil
}
