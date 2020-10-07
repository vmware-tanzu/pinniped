// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"fmt"
	"net/url"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

	configinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

const (
	issuerConfigMapKey = "issuer"
)

// IssuerSetter can be notified of a valid issuer with its SetIssuer function. If there is no
// longer any valid issuer, then nil can be passed to this interface.
//
// If the IssuerSetter doesn't like the provided issuer, it can return an error.
//
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type IssuerSetter interface {
	SetIssuer(issuer *url.URL) error
}

type dynamicConfigWatcherController struct {
	issuerSetter IssuerSetter
	opcInformer  configinformers.OIDCProviderConfigInformer
}

// NewDynamicConfigWatcherController creates a controllerlib.Controller that watches
// OIDCProviderConfig objects and notifies a callback object of their creation or deletion.
func NewDynamicConfigWatcherController(
	issuerObserver IssuerSetter,
	opcInformer configinformers.OIDCProviderConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "DynamicConfigWatcherController",
			Syncer: &dynamicConfigWatcherController{
				issuerSetter: issuerObserver,
				opcInformer:  opcInformer,
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
func (c *dynamicConfigWatcherController) Sync(ctx controllerlib.Context) error {
	// TODO Watch the configmap to find the issuer name, ingress url, etc.
	// TODO Update some kind of in-memory representation of the configuration so the discovery endpoint can use it.
	// TODO The discovery endpoint would return an error until all missing configuration options are
	// filled in.

	opc, err := c.opcInformer.
		Lister().
		OIDCProviderConfigs(ctx.Key.Namespace).
		Get(ctx.Key.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s oidcproviderconfig: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	if notFound {
		klog.InfoS(
			"dynamicConfigWatcherController Sync found no oidcproviderconfig",
			"oidcproviderconfig",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		c.issuerSetter.SetIssuer(nil)
		return nil
	}

	url, err := url.Parse(opc.Spec.Issuer)
	if err != nil {
		klog.InfoS(
			"dynamicConfigWatcherController Sync failed to parse issuer",
			"err",
			err,
		)
		return nil
	}

	klog.InfoS(
		"dynamicConfigWatcherController Sync issuer",
		"oidcproviderconfig",
		klog.KObj(opc),
		"issuer",
		url,
	)
	if err := c.issuerSetter.SetIssuer(url); err != nil {
		klog.InfoS(
			"dynamicConfigWatcherController Sync failed to set issuer",
			"err",
			err,
		)
	}

	return nil
}
