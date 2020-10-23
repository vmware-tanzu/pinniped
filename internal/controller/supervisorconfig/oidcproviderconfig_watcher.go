// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"
	"net/url"
	"strings"

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
			pinnipedcontroller.MatchAnythingFilter(),
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

	// Make a map of issuer strings -> count of how many times we saw that issuer string.
	// This will help us complain when there are duplicate issuer strings.
	// Also make a helper function for forming keys into this map.
	issuerCounts := make(map[string]int)
	issuerURLToIssuerKey := func(issuerURL *url.URL) string {
		return fmt.Sprintf("%s://%s%s", issuerURL.Scheme, strings.ToLower(issuerURL.Host), issuerURL.Path)
	}

	// Make a map of issuer addresses -> set of unique secret names. This will help us complain when
	// multiple OIDCProviderConfigs have the same issuer address (host) component but specify
	// different TLS serving Secrets. Doesn't make sense to have the one address use more than one
	// TLS cert. Also make a helper function for forming keys into this map.
	uniqueSecretNamesPerIssuerAddress := make(map[string]map[string]bool)
	issuerURLToHostKey := func(issuerURL *url.URL) string {
		return strings.ToLower(issuerURL.Host)
	}

	for _, opc := range all {
		issuerURL, err := url.Parse(opc.Spec.Issuer)
		if err != nil {
			continue // Skip url parse errors because they will be validated again below.
		}

		issuerCounts[issuerURLToIssuerKey(issuerURL)]++

		setOfSecretNames := uniqueSecretNamesPerIssuerAddress[issuerURLToHostKey(issuerURL)]
		if setOfSecretNames == nil {
			setOfSecretNames = make(map[string]bool)
			uniqueSecretNamesPerIssuerAddress[issuerURLToHostKey(issuerURL)] = setOfSecretNames
		}
		setOfSecretNames[opc.Spec.SecretName] = true
	}

	errs := multierror.New()

	oidcProviders := make([]*provider.OIDCProvider, 0)
	for _, opc := range all {
		issuerURL, urlParseErr := url.Parse(opc.Spec.Issuer)

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil {
			if issuerCount := issuerCounts[issuerURLToIssuerKey(issuerURL)]; issuerCount > 1 {
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
		}

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil && len(uniqueSecretNamesPerIssuerAddress[issuerURLToHostKey(issuerURL)]) > 1 {
			if err := c.updateStatus(
				ctx.Context,
				opc.Namespace,
				opc.Name,
				configv1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatus,
				"Issuers with the same address must use the same secretName: "+issuerURLToHostKey(issuerURL),
			); err != nil {
				errs.Add(fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		oidcProvider, err := provider.NewOIDCProvider(opc.Spec.Issuer) // This validates the Issuer URL.
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
		opc.Status.LastUpdateTime = timePtr(metav1.NewTime(c.clock.Now()))
		_, err = c.client.ConfigV1alpha1().OIDCProviderConfigs(namespace).Update(ctx, opc, metav1.UpdateOptions{})
		return err
	})
}

func timePtr(t metav1.Time) *metav1.Time { return &t }
