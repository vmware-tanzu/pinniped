// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"

	"go.pinniped.dev/internal/multierror"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
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
	clock          clock.Clock
	client         pinnipedclientset.Interface
	opcInformer    configinformers.OIDCProviderConfigInformer
}

// NewOIDCProviderConfigWatcherController creates a controllerlib.Controller that watches
// OIDCProviderConfig objects and notifies a callback object of the collection of provider configs.
func NewOIDCProviderConfigWatcherController(
	providerSetter ProvidersSetter,
	clock clock.Clock,
	client pinnipedclientset.Interface,
	opcInformer configinformers.OIDCProviderConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "OIDCProviderConfigWatcherController",
			Syncer: &oidcProviderConfigWatcherController{
				providerSetter: providerSetter,
				clock:          clock,
				client:         client,
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

	issuerCounts := make(map[string]int)
	for _, opc := range all {
		issuerCounts[opc.Spec.Issuer]++
	}

	errs := multierror.New()

	oidcProviders := make([]*provider.OIDCProvider, 0)
	for _, opc := range all {
		if issuerCount := issuerCounts[opc.Spec.Issuer]; issuerCount > 1 {
			if err := c.updateStatus(
				ctx.Context,
				opc.Namespace,
				opc.Name,
				configv1alpha1.DuplicateOIDCProviderStatus,
				"Duplicate issuer: "+opc.Spec.Issuer,
			); err != nil {
				errs.Add(fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		oidcProvider, err := provider.NewOIDCProvider(opc.Spec.Issuer)
		if err != nil {
			if err := c.updateStatus(
				ctx.Context,
				opc.Namespace,
				opc.Name,
				configv1alpha1.InvalidOIDCProviderStatus,
				"Invalid: "+err.Error(),
			); err != nil {
				errs.Add(fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		if err := c.updateStatus(
			ctx.Context,
			opc.Namespace,
			opc.Name,
			configv1alpha1.SuccessOIDCProviderStatus,
			"Provider successfully created",
		); err != nil {
			errs.Add(fmt.Errorf("could not update status: %w", err))
			continue
		}
		oidcProviders = append(oidcProviders, oidcProvider)
	}

	c.providerSetter.SetProviders(oidcProviders...)

	return errs.ErrOrNil()
}

func (c *oidcProviderConfigWatcherController) updateStatus(
	ctx context.Context,
	namespace, name string,
	status configv1alpha1.OIDCProviderStatus,
	message string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		opc, err := c.client.ConfigV1alpha1().OIDCProviderConfigs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get failed: %w", err)
		}

		if opc.Status.Status == status && opc.Status.Message == message {
			return nil
		}

		klog.InfoS(
			"attempting status update",
			"openidproviderconfig",
			klog.KRef(namespace, name),
			"status",
			status,
			"message",
			message,
		)
		opc.Status.Status = status
		opc.Status.Message = message
		_, err = c.client.ConfigV1alpha1().OIDCProviderConfigs(namespace).Update(ctx, opc, metav1.UpdateOptions{})
		return err
	})
}
