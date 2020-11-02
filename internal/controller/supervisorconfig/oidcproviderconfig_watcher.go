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

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions/config/v1alpha1"
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

type oidcProviderWatcherController struct {
	providerSetter ProvidersSetter
	clock          clock.Clock
	client         pinnipedclientset.Interface
	opcInformer    configinformers.OIDCProviderInformer
}

// NewOIDCProviderWatcherController creates a controllerlib.Controller that watches
// OIDCProvider objects and notifies a callback object of the collection of provider configs.
func NewOIDCProviderWatcherController(
	providerSetter ProvidersSetter,
	clock clock.Clock,
	client pinnipedclientset.Interface,
	opcInformer configinformers.OIDCProviderInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "OIDCProviderWatcherController",
			Syncer: &oidcProviderWatcherController{
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
func (c *oidcProviderWatcherController) Sync(ctx controllerlib.Context) error {
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

	// Make a map of issuer hostnames -> set of unique secret names. This will help us complain when
	// multiple OIDCProviders have the same issuer hostname (excluding port) but specify
	// different TLS serving Secrets. Doesn't make sense to have the one address use more than one
	// TLS cert. Ignore ports because SNI information on the incoming requests is not going to include
	// port numbers. Also make a helper function for forming keys into this map.
	uniqueSecretNamesPerIssuerAddress := make(map[string]map[string]bool)
	issuerURLToHostnameKey := lowercaseHostWithoutPort

	for _, opc := range all {
		issuerURL, err := url.Parse(opc.Spec.Issuer)
		if err != nil {
			continue // Skip url parse errors because they will be validated again below.
		}

		issuerCounts[issuerURLToIssuerKey(issuerURL)]++

		setOfSecretNames := uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]
		if setOfSecretNames == nil {
			setOfSecretNames = make(map[string]bool)
			uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)] = setOfSecretNames
		}
		setOfSecretNames[opc.Spec.SNICertificateSecretName] = true
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
					configv1alpha1.DuplicateOIDCProviderStatusCondition,
					"Duplicate issuer: "+opc.Spec.Issuer,
				); err != nil {
					errs.Add(fmt.Errorf("could not update status: %w", err))
				}
				continue
			}
		}

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil && len(uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]) > 1 {
			if err := c.updateStatus(
				ctx.Context,
				opc.Namespace,
				opc.Name,
				configv1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatusCondition,
				"Issuers with the same DNS hostname (address not including port) must use the same secretName: "+issuerURLToHostnameKey(issuerURL),
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
				configv1alpha1.InvalidOIDCProviderStatusCondition,
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
			configv1alpha1.SuccessOIDCProviderStatusCondition,
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

func (c *oidcProviderWatcherController) updateStatus(
	ctx context.Context,
	namespace, name string,
	status configv1alpha1.OIDCProviderStatusCondition,
	message string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		opc, err := c.client.ConfigV1alpha1().OIDCProviders(namespace).Get(ctx, name, metav1.GetOptions{})
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
		_, err = c.client.ConfigV1alpha1().OIDCProviders(namespace).Update(ctx, opc, metav1.UpdateOptions{})
		return err
	})
}

func timePtr(t metav1.Time) *metav1.Time { return &t }
