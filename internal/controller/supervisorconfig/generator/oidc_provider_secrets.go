// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	configinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

type oidcProviderSecretsController struct {
	secretHelper   SecretHelper
	kubeClient     kubernetes.Interface
	opcInformer    configinformers.OIDCProviderInformer
	secretInformer corev1informers.SecretInformer
}

// NewOIDCProviderSecretsController returns a controllerlib.Controller that ensures a child Secret
// always exists for a parent OIDCProvider. It does this using the provided secretHelper, which
// provides the parent/child mapping logic.
func NewOIDCProviderSecretsController(
	secretHelper SecretHelper,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	opcInformer configinformers.OIDCProviderInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: fmt.Sprintf("%s%s", secretHelper.Name(), "controller"),
			Syncer: &oidcProviderSecretsController{
				secretHelper:   secretHelper,
				kubeClient:     kubeClient,
				secretInformer: secretInformer,
				opcInformer:    opcInformer,
			},
		},
		// We want to be notified when a OPC's secret gets updated or deleted. When this happens, we
		// should get notified via the corresponding OPC key.
		// TODO: de-dup me (jwks_writer.go).
		withInformer(
			secretInformer,
			pinnipedcontroller.SimpleFilter(isOPControllee, func(obj metav1.Object) controllerlib.Key {
				if isOPControllee(obj) {
					controller := metav1.GetControllerOf(obj)
					return controllerlib.Key{
						Name:      controller.Name,
						Namespace: obj.GetNamespace(),
					}
				}
				return controllerlib.Key{}
			}),
			controllerlib.InformerOption{},
		),
		// We want to be notified when anything happens to an OPC.
		withInformer(
			opcInformer,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

func (c *oidcProviderSecretsController) Sync(ctx controllerlib.Context) error {
	op, err := c.opcInformer.Lister().OIDCProviders(ctx.Key.Namespace).Get(ctx.Key.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf(
			"failed to get %s/%s OIDCProvider: %w",
			ctx.Key.Namespace,
			ctx.Key.Name,
			err,
		)
	}

	if notFound {
		// The corresponding secret to this OP should have been garbage collected since it should have
		// had this OP as its owner.
		plog.Debug(
			"oidcprovider deleted",
			"oidcprovider",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	newSecret, err := c.secretHelper.Generate(op)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	secretNeedsUpdate, existingSecret, err := c.secretNeedsUpdate(op, newSecret.Name)
	if err != nil {
		return fmt.Errorf("failed to determine secret status: %w", err)
	}
	if !secretNeedsUpdate {
		// Secret is up to date - we are good to go.
		plog.Debug(
			"secret is up to date",
			"oidcprovider",
			klog.KObj(op),
			"secret",
			klog.KObj(existingSecret),
		)
		c.secretHelper.Notify(op, existingSecret)
		return nil
	}

	// If the OP does not have a secret associated with it, that secret does not exist, or the secret
	// is invalid, we will create a new secret.
	if err := c.createOrUpdateSecret(ctx.Context, op, &newSecret); err != nil {
		return fmt.Errorf("failed to create or update secret: %w", err)
	}
	plog.Debug("created/updated secret", "oidcprovider", klog.KObj(op), "secret", klog.KObj(newSecret))

	c.secretHelper.Notify(op, newSecret)

	return nil
}

// secretNeedsUpdate returns whether or not the Secret, with name secretName, for OIDCProvider op
// needs to be updated. It returns the existing secret as its second argument.
func (c *oidcProviderSecretsController) secretNeedsUpdate(
	op *configv1alpha1.OIDCProvider,
	secretName string,
) (bool, *corev1.Secret, error) {
	// This OPC says it has a secret associated with it. Let's try to get it from the cache.
	secret, err := c.secretInformer.Lister().Secrets(op.Namespace).Get(secretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return false, nil, fmt.Errorf("cannot get secret: %w", err)
	}
	if notFound {
		// If we can't find the secret, let's assume we need to create it.
		return true, nil, nil
	}

	if !c.secretHelper.IsValid(op, secret) {
		// If this secret is invalid, we need to generate a new one.
		return true, secret, nil
	}

	return false, secret, nil
}

func (c *oidcProviderSecretsController) createOrUpdateSecret(
	ctx context.Context,
	op *configv1alpha1.OIDCProvider,
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
		if c.secretHelper.IsValid(op, oldSecret) {
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
