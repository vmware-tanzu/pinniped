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

// NewLegacyServiceAccountTokenCleanupController creates a controller whose purpose is to delete a legacy Secret
// that was created by installation of older versions of the Pinniped Concierge which is no longer needed.
// This Secret was used to request and to hold a long-lived service account token which was used by the Concierge
// impersonation proxy. It has been replaced by a goroutine which requests short-lived service account tokens
// by making calls to the Kubernetes API server, without any need to read or write the tokens to a Secret.
// Since the old Secret contains a long-lived token, we try to delete it here. That Secret may not exist if the user
// never installed an old version of the Concierge, in which case this controller should do pretty much nothing.
func NewLegacyServiceAccountTokenCleanupController(
	namespace string,
	legacySecretName string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	logger plog.Logger,
) controllerlib.Controller {
	name := "legacy-service-account-token-cleanup-controller"
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

	foundSecret := false
	for _, secret := range secrets {
		if secret.Name == c.legacySecretName && secret.Type == corev1.SecretTypeServiceAccountToken {
			foundSecret = true
		}
	}

	c.logger.Debug(
		fmt.Sprintf("%s controller checked for legacy secret", c.name),
		"secretName", c.legacySecretName,
		"secretNamespace", c.namespace,
		"secretType", corev1.SecretTypeServiceAccountToken,
		"foundSecret", foundSecret,
	)

	if foundSecret {
		err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(syncCtx.Context, c.legacySecretName, metav1.DeleteOptions{})

		if err != nil {
			return fmt.Errorf("unable to delete secret %s in namespace %s: %w", c.legacySecretName, c.namespace, err)
		}

		c.logger.Debug(
			fmt.Sprintf("%s controller succcessfully deleted legacy secret", c.name),
			"secretName", c.legacySecretName,
			"secretNamespace", c.namespace,
			"secretType", corev1.SecretTypeServiceAccountToken,
		)
	}

	return nil
}
