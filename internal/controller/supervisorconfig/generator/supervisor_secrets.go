// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secretgenerator provides a supervisorSecretsController that can ensure existence of a generated secret.
package generator

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

// generateKey is stubbed out for the purpose of testing. The default behavior is to generate a symmetric key.
//nolint:gochecknoglobals
var generateKey = generateSymmetricKey

type supervisorSecretsController struct {
	owner          *appsv1.Deployment
	labels         map[string]string
	kubeClient     kubernetes.Interface
	secretInformer corev1informers.SecretInformer
	setCacheFunc   func(secret []byte)
}

// NewSupervisorSecretsController instantiates a new controllerlib.Controller which will ensure existence of a generated secret.
func NewSupervisorSecretsController(
	// TODO: generate the name for the secret and label the secret with the UID of the owner? So that we don't have naming conflicts if the user has already created a Secret with that name.
	owner *appsv1.Deployment,
	labels map[string]string,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	setCacheFunc func(secret []byte),
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	initialEventFunc pinnipedcontroller.WithInitialEventOptionFunc,
) controllerlib.Controller {
	c := supervisorSecretsController{
		owner:          owner,
		labels:         labels,
		kubeClient:     kubeClient,
		secretInformer: secretInformer,
		setCacheFunc:   setCacheFunc,
	}
	return controllerlib.New(
		controllerlib.Config{Name: owner.Name + "-secret-generator", Syncer: &c},
		withInformer(
			secretInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return metav1.IsControlledBy(obj, owner)
			}, nil),
			controllerlib.InformerOption{},
		),
		initialEventFunc(controllerlib.Key{
			Namespace: owner.Namespace,
			Name:      owner.Name + "-key",
		}),
	)
}

// Sync implements controllerlib.Syncer.Sync().
func (c *supervisorSecretsController) Sync(ctx controllerlib.Context) error {
	secret, err := c.secretInformer.Lister().Secrets(ctx.Key.Namespace).Get(ctx.Key.Name)
	isNotFound := k8serrors.IsNotFound(err)
	if !isNotFound && err != nil {
		return fmt.Errorf("failed to list secret %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	secretNeedsUpdate := isNotFound || !isValid(secret)
	if !secretNeedsUpdate {
		plog.Debug("secret is up to date", "secret", klog.KObj(secret))
		c.setCacheFunc(secret.Data[symmetricSecretDataKey])
		return nil
	}

	newSecret, err := generateSecret(ctx.Key.Namespace, ctx.Key.Name, c.labels, secretDataFunc, c.owner)
	if err != nil {
		return fmt.Errorf("failed to generate secret: %w", err)
	}

	if isNotFound {
		err = c.createSecret(ctx.Context, newSecret)
	} else {
		err = c.updateSecret(ctx.Context, &newSecret, ctx.Key.Name)
	}
	if err != nil {
		return fmt.Errorf("failed to create/update secret %s/%s: %w", newSecret.Namespace, newSecret.Name, err)
	}

	c.setCacheFunc(newSecret.Data[symmetricSecretDataKey])

	return nil
}

func (c *supervisorSecretsController) createSecret(ctx context.Context, newSecret *corev1.Secret) error {
	_, err := c.kubeClient.CoreV1().Secrets(newSecret.Namespace).Create(ctx, newSecret, metav1.CreateOptions{})
	return err
}

func (c *supervisorSecretsController) updateSecret(ctx context.Context, newSecret **corev1.Secret, secretName string) error {
	secrets := c.kubeClient.CoreV1().Secrets((*newSecret).Namespace)
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		currentSecret, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
		isNotFound := k8serrors.IsNotFound(err)
		if !isNotFound && err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}

		if isNotFound {
			if err := c.createSecret(ctx, *newSecret); err != nil {
				return fmt.Errorf("failed to create secret: %w", err)
			}
			return nil
		}

		if isValid(currentSecret) {
			*newSecret = currentSecret
			return nil
		}

		currentSecret.Type = (*newSecret).Type
		currentSecret.Data = (*newSecret).Data

		_, err = secrets.Update(ctx, currentSecret, metav1.UpdateOptions{})
		return err
	})
}
