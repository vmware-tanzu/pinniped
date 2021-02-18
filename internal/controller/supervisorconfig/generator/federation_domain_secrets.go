// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

type federationDomainSecretsController struct {
	secretHelper             SecretHelper
	secretRefFunc            func(domain *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference
	kubeClient               kubernetes.Interface
	pinnipedClient           pinnipedclientset.Interface
	federationDomainInformer configinformers.FederationDomainInformer
	secretInformer           corev1informers.SecretInformer
}

// NewFederationDomainSecretsController returns a controllerlib.Controller that ensures a child Secret
// always exists for a parent FederationDomain. It does this using the provided secretHelper, which
// provides the parent/child mapping logic.
func NewFederationDomainSecretsController(
	secretHelper SecretHelper,
	secretRefFunc func(domain *configv1alpha1.FederationDomainStatus) *corev1.LocalObjectReference,
	kubeClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	federationDomainInformer configinformers.FederationDomainInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: fmt.Sprintf("%s%s", secretHelper.NamePrefix(), "controller"),
			Syncer: &federationDomainSecretsController{
				secretHelper:             secretHelper,
				secretRefFunc:            secretRefFunc,
				kubeClient:               kubeClient,
				pinnipedClient:           pinnipedClient,
				secretInformer:           secretInformer,
				federationDomainInformer: federationDomainInformer,
			},
		},
		// We want to be notified when a FederationDomain's secret gets updated or deleted. When this happens, we
		// should get notified via the corresponding FederationDomain key.
		withInformer(
			secretInformer,
			pinnipedcontroller.SimpleFilter(secretHelper.Handles, pinnipedcontroller.SecretIsControlledByParentFunc(secretHelper.Handles)),
			controllerlib.InformerOption{},
		),
		// We want to be notified when anything happens to an FederationDomain.
		withInformer(
			federationDomainInformer,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

func (c *federationDomainSecretsController) Sync(ctx controllerlib.Context) error {
	federationDomain, err := c.federationDomainInformer.Lister().FederationDomains(ctx.Key.Namespace).Get(ctx.Key.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf(
			"failed to get %s/%s FederationDomain: %w",
			ctx.Key.Namespace,
			ctx.Key.Name,
			err,
		)
	}

	if notFound {
		// The corresponding secret to this FederationDomain should have been garbage collected since it should have
		// had this FederationDomain as its owner.
		plog.Debug(
			"federationdomain deleted",
			"federationdomain",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	federationDomain = federationDomain.DeepCopy()
	newSecret, err := c.secretHelper.Generate(federationDomain)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	secretNeedsUpdate, existingSecret, err := c.secretNeedsUpdate(federationDomain, newSecret.Name)
	if err != nil {
		return fmt.Errorf("failed to determine secret status: %w", err)
	}
	if !secretNeedsUpdate {
		// Secret is up to date - we are good to go.
		plog.Debug(
			"secret is up to date",
			"federationdomain",
			klog.KObj(federationDomain),
			"secret",
			klog.KObj(existingSecret),
		)

		federationDomain = c.secretHelper.ObserveActiveSecretAndUpdateParentFederationDomain(federationDomain, existingSecret)
		if err := c.updateFederationDomainStatus(ctx.Context, federationDomain); err != nil {
			return fmt.Errorf("failed to update federationdomain: %w", err)
		}
		plog.Debug("updated federationdomain", "federationdomain", klog.KObj(federationDomain), "secret", klog.KObj(newSecret))

		return nil
	}

	// If the FederationDomain does not have a secret associated with it, that secret does not exist, or the secret
	// is invalid, we will create a new secret.
	if err := c.createOrUpdateSecret(ctx.Context, federationDomain, &newSecret); err != nil {
		return fmt.Errorf("failed to create or update secret: %w", err)
	}
	plog.Debug("created/updated secret", "federationdomain", klog.KObj(federationDomain), "secret", klog.KObj(newSecret))

	federationDomain = c.secretHelper.ObserveActiveSecretAndUpdateParentFederationDomain(federationDomain, newSecret)
	if err := c.updateFederationDomainStatus(ctx.Context, federationDomain); err != nil {
		return fmt.Errorf("failed to update federationdomain: %w", err)
	}
	plog.Debug("updated federationdomain", "federationdomain", klog.KObj(federationDomain), "secret", klog.KObj(newSecret))

	return nil
}

// secretNeedsUpdate returns whether or not the Secret, with name secretName, for the federationDomain param
// needs to be updated. It returns the existing secret as its second argument.
func (c *federationDomainSecretsController) secretNeedsUpdate(
	federationDomain *configv1alpha1.FederationDomain,
	secretName string,
) (bool, *corev1.Secret, error) {
	// This FederationDomain says it has a secret associated with it. Let's try to get it from the cache.
	secret, err := c.secretInformer.Lister().Secrets(federationDomain.Namespace).Get(secretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return false, nil, fmt.Errorf("cannot get secret: %w", err)
	}
	if notFound {
		// If we can't find the secret, let's assume we need to create it.
		return true, nil, nil
	}

	if !c.secretHelper.IsValid(federationDomain, secret) {
		// If this secret is invalid, we need to generate a new one.
		return true, secret, nil
	}

	return false, secret, nil
}

func (c *federationDomainSecretsController) createOrUpdateSecret(
	ctx context.Context,
	federationDomain *configv1alpha1.FederationDomain,
	newSecret **corev1.Secret,
) error {
	secretClient := c.kubeClient.CoreV1().Secrets((*newSecret).Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldSecret, err := secretClient.Get(ctx, (*newSecret).Name, metav1.GetOptions{})
		notFound := k8serrors.IsNotFound(err)
		if err != nil && !notFound {
			return fmt.Errorf("failed to get secret %s/%s: %w", (*newSecret).Namespace, (*newSecret).Name, err)
		}

		if notFound {
			// New secret doesn't exist, so create it.
			_, err := secretClient.Create(ctx, *newSecret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create secret %s/%s: %w", (*newSecret).Namespace, (*newSecret).Name, err)
			}
			return nil
		}

		// New secret already exists, so ensure it is up to date.
		if c.secretHelper.IsValid(federationDomain, oldSecret) {
			// If the secret already has valid a valid Secret, then we are good to go and we don't need an
			// update.
			*newSecret = oldSecret
			return nil
		}

		oldSecret.Labels = (*newSecret).Labels
		oldSecret.Type = (*newSecret).Type
		oldSecret.Data = (*newSecret).Data
		*newSecret = oldSecret
		_, err = secretClient.Update(ctx, oldSecret, metav1.UpdateOptions{})
		return err
	})
}

func (c *federationDomainSecretsController) updateFederationDomainStatus(
	ctx context.Context,
	newFederationDomain *configv1alpha1.FederationDomain,
) error {
	federationDomainClient := c.pinnipedClient.ConfigV1alpha1().FederationDomains(newFederationDomain.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldFederationDomain, err := federationDomainClient.Get(ctx, newFederationDomain.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get federationdomain %s/%s: %w", newFederationDomain.Namespace, newFederationDomain.Name, err)
		}

		oldFederationDomainSecretRef := c.secretRefFunc(&oldFederationDomain.Status)
		newFederationDomainSecretRef := c.secretRefFunc(&newFederationDomain.Status)
		if reflect.DeepEqual(oldFederationDomainSecretRef, newFederationDomainSecretRef) {
			return nil
		}

		*oldFederationDomainSecretRef = *newFederationDomainSecretRef
		_, err = federationDomainClient.UpdateStatus(ctx, oldFederationDomain, metav1.UpdateOptions{})
		return err
	})
}
