// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

// ProvidersSetter can be notified of all known valid providers with its SetIssuer function.
// If there are no longer any valid issuers, then it can be called with no arguments.
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type ProvidersSetter interface {
	SetProviders(federationDomains ...*provider.FederationDomainIssuer)
}

type federationDomainWatcherController struct {
	providerSetter           ProvidersSetter
	clock                    clock.Clock
	client                   pinnipedclientset.Interface
	federationDomainInformer configinformers.FederationDomainInformer
}

// NewFederationDomainWatcherController creates a controllerlib.Controller that watches
// FederationDomain objects and notifies a callback object of the collection of provider configs.
func NewFederationDomainWatcherController(
	providerSetter ProvidersSetter,
	clock clock.Clock,
	client pinnipedclientset.Interface,
	federationDomainInformer configinformers.FederationDomainInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "FederationDomainWatcherController",
			Syncer: &federationDomainWatcherController{
				providerSetter:           providerSetter,
				clock:                    clock,
				client:                   client,
				federationDomainInformer: federationDomainInformer,
			},
		},
		withInformer(
			federationDomainInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *federationDomainWatcherController) Sync(ctx controllerlib.Context) error {
	federationDomains, err := c.federationDomainInformer.Lister().List(labels.Everything())
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
	// multiple FederationDomains have the same issuer hostname (excluding port) but specify
	// different TLS serving Secrets. Doesn't make sense to have the one address use more than one
	// TLS cert. Ignore ports because SNI information on the incoming requests is not going to include
	// port numbers. Also make a helper function for forming keys into this map.
	uniqueSecretNamesPerIssuerAddress := make(map[string]map[string]bool)
	issuerURLToHostnameKey := lowercaseHostWithoutPort

	for _, federationDomain := range federationDomains {
		issuerURL, err := url.Parse(federationDomain.Spec.Issuer)
		if err != nil {
			continue // Skip url parse errors because they will be validated again below.
		}

		issuerCounts[issuerURLToIssuerKey(issuerURL)]++

		setOfSecretNames := uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]
		if setOfSecretNames == nil {
			setOfSecretNames = make(map[string]bool)
			uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)] = setOfSecretNames
		}
		if federationDomain.Spec.TLS != nil {
			setOfSecretNames[federationDomain.Spec.TLS.SecretName] = true
		}
	}

	var errs []error

	federationDomainIssuers := make([]*provider.FederationDomainIssuer, 0)
	for _, federationDomain := range federationDomains {
		issuerURL, urlParseErr := url.Parse(federationDomain.Spec.Issuer)

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil {
			if issuerCount := issuerCounts[issuerURLToIssuerKey(issuerURL)]; issuerCount > 1 {
				if err := c.updateStatus(
					ctx.Context,
					federationDomain.Namespace,
					federationDomain.Name,
					configv1alpha1.DuplicateFederationDomainStatusCondition,
					"Duplicate issuer: "+federationDomain.Spec.Issuer,
				); err != nil {
					errs = append(errs, fmt.Errorf("could not update status: %w", err))
				}
				continue
			}
		}

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil && len(uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]) > 1 {
			if err := c.updateStatus(
				ctx.Context,
				federationDomain.Namespace,
				federationDomain.Name,
				configv1alpha1.SameIssuerHostMustUseSameSecretFederationDomainStatusCondition,
				"Issuers with the same DNS hostname (address not including port) must use the same secretName: "+issuerURLToHostnameKey(issuerURL),
			); err != nil {
				errs = append(errs, fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		federationDomainIssuer, err := provider.NewFederationDomainIssuer(federationDomain.Spec.Issuer) // This validates the Issuer URL.
		if err != nil {
			if err := c.updateStatus(
				ctx.Context,
				federationDomain.Namespace,
				federationDomain.Name,
				configv1alpha1.InvalidFederationDomainStatusCondition,
				"Invalid: "+err.Error(),
			); err != nil {
				errs = append(errs, fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		if err := c.updateStatus(
			ctx.Context,
			federationDomain.Namespace,
			federationDomain.Name,
			configv1alpha1.SuccessFederationDomainStatusCondition,
			"Provider successfully created",
		); err != nil {
			errs = append(errs, fmt.Errorf("could not update status: %w", err))
			continue
		}

		federationDomainIssuers = append(federationDomainIssuers, federationDomainIssuer)
	}

	c.providerSetter.SetProviders(federationDomainIssuers...)

	return errors.NewAggregate(errs)
}

func (c *federationDomainWatcherController) updateStatus(
	ctx context.Context,
	namespace, name string,
	status configv1alpha1.FederationDomainStatusCondition,
	message string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		federationDomain, err := c.client.ConfigV1alpha1().FederationDomains(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get failed: %w", err)
		}

		if federationDomain.Status.Status == status && federationDomain.Status.Message == message {
			return nil
		}

		plog.Debug(
			"attempting status update",
			"federationdomain",
			klog.KRef(namespace, name),
			"status",
			status,
			"message",
			message,
		)
		federationDomain.Status.Status = status
		federationDomain.Status.Message = message
		federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(c.clock.Now()))
		_, err = c.client.ConfigV1alpha1().FederationDomains(namespace).UpdateStatus(ctx, federationDomain, metav1.UpdateOptions{})
		return err
	})
}

func timePtr(t metav1.Time) *metav1.Time { return &t }
