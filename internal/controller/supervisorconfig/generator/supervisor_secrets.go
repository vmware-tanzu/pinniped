// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secretgenerator provides a supervisorSecretsController that can ensure existence of a generated secret.
package generator

import (
	"context"
	"crypto/rand"
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
	labels         map[string]string
	kubeClient     kubernetes.Interface
	secretInformer corev1informers.SecretInformer
	setCacheFunc   func(secret []byte)
}

// NewSupervisorSecretsController instantiates a new controllerlib.Controller which will ensure existence of a generated secret.
func NewSupervisorSecretsController(
	owner *appsv1.Deployment,
	labels map[string]string,
	kubeClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	setCacheFunc func(secret []byte),
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	initialEventFunc pinnipedcontroller.WithInitialEventOptionFunc,
) controllerlib.Controller {
	c := supervisorSecretsController{
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
				secret, ok := obj.(*corev1.Secret)
				if !ok {
					return false
				}
				if secret.Type != SupervisorCSRFSigningKeySecretType {
					return false
				}
				return true
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

	secretNeedsUpdate := isNotFound || !isValid(secret, c.labels)
	if !secretNeedsUpdate {
		plog.Debug("secret is up to date", "secret", klog.KObj(secret))
		c.setCacheFunc(secret.Data[symmetricSecretDataKey])
		return nil
	}

	newSecret, err := generateSecret(ctx.Key.Namespace, ctx.Key.Name, c.labels, secretDataFunc)
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

		if isValid(currentSecret, c.labels) {
			*newSecret = currentSecret
			return nil
		}

		currentSecret.Type = (*newSecret).Type
		currentSecret.Data = (*newSecret).Data
		for key, value := range c.labels {
			currentSecret.Labels[key] = value
		}

		_, err = secrets.Update(ctx, currentSecret, metav1.UpdateOptions{})
		return err
	})
}

func generateSymmetricKey() ([]byte, error) {
	b := make([]byte, symmetricKeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func isValid(secret *corev1.Secret, labels map[string]string) bool {
	if secret.Type != SupervisorCSRFSigningKeySecretType {
		return false
	}

	data, ok := secret.Data[symmetricSecretDataKey]
	if !ok {
		return false
	}
	if len(data) != symmetricKeySize {
		return false
	}

	for key, value := range labels {
		if secret.Labels[key] != value {
			return false
		}
	}

	return true
}

func secretDataFunc() (map[string][]byte, error) {
	symmetricKey, err := generateKey()
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		symmetricSecretDataKey: symmetricKey,
	}, nil
}

func generateSecret(namespace, name string, labels map[string]string, secretDataFunc func() (map[string][]byte, error)) (*corev1.Secret, error) {
	secretData, err := secretDataFunc()
	if err != nil {
		return nil, err
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Type: SupervisorCSRFSigningKeySecretType,
		Data: secretData,
	}, nil
}
