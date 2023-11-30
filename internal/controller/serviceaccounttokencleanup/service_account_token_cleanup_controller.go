// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serviceaccounttokencleanup

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

func NewServiceAccountTokenCleanupController(
	namespace string,
	legacySecretName string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	logger plog.Logger,
) controllerlib.Controller {
	name := "service-account-token-cleanup-controller"
	return controllerlib.New(controllerlib.Config{
		Name: name,
		Syncer: &serviceAccountTokenCleanupController{
			name:             name,
			namespace:        namespace,
			legacySecretName: legacySecretName,
			k8sClient:        k8sClient,
			secretInformer:   secretInformer,
			logger:           logger.WithName(name),
		},
	},
		withInformer(
			secretInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				secret, ok := obj.(*corev1.Secret)

				return obj.GetNamespace() == namespace &&
					obj.GetName() == legacySecretName &&
					ok &&
					secret.Type == corev1.SecretTypeServiceAccountToken
			}),
			controllerlib.InformerOption{},
		))
}

type serviceAccountTokenCleanupController struct {
	name             string
	namespace        string
	legacySecretName string
	k8sClient        kubernetes.Interface
	secretInformer   corev1informers.SecretInformer
	logger           plog.Logger
}

func (c serviceAccountTokenCleanupController) Sync(syncCtx controllerlib.Context) error {
	secrets, err := c.secretInformer.Lister().Secrets(c.namespace).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("unable to list all secrets in namespace %s: %w", c.namespace, err)
	}
	c.logger.Info(fmt.Sprintf("You have now arrived in the %s controller, found %d secrets", c.name, len(secrets)))

	foundSecret := false
	for _, secret := range secrets {
		if secret.Name == c.legacySecretName && secret.Type == corev1.SecretTypeServiceAccountToken {
			foundSecret = true
		}
	}

	c.logger.Info(fmt.Sprintf(
		"The %s controller has found a secret of name %s to delete with type %s",
		c.name,
		c.legacySecretName,
		corev1.SecretTypeServiceAccountToken,
	))

	if foundSecret {
		err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(syncCtx.Context, c.legacySecretName, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("unable to delete secret %s in namespace %s: %w", c.legacySecretName, c.namespace, err)
		}
	}

	return nil
}
