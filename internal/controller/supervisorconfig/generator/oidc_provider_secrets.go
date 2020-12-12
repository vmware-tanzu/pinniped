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
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

const (
	// TODO should this live on `provider.OIDCProvider` ?
	opcKind = "OIDCProvider" // TODO: deduplicate - internal/controller/supervisorconfig/jwks_writer.go
)

// jwkController holds the fields necessary for the JWKS controller to communicate with OPC's and
// secrets, both via a cache and via the API.
type oidcProviderSecretsController struct {
	secretNameFunc func(*configv1alpha1.OIDCProvider) string
	secretLabels   map[string]string
	secretDataFunc func() (map[string][]byte, error)
	pinnipedClient pinnipedclientset.Interface
	kubeClient     kubernetes.Interface
	opcInformer    configinformers.OIDCProviderInformer
	secretInformer corev1informers.SecretInformer
}

func NewOIDCProviderSecretsController(
	secretNameFunc func(*configv1alpha1.OIDCProvider) string,
	secretLabels map[string]string,
	secretDataFunc func() (map[string][]byte, error),
	kubeClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	opcInformer configinformers.OIDCProviderInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "JWKSController",
			Syncer: &oidcProviderSecretsController{
				secretNameFunc: secretNameFunc,
				secretLabels:   secretLabels,
				secretDataFunc: secretDataFunc,
				kubeClient:     kubeClient,
				pinnipedClient: pinnipedClient,
				secretInformer: secretInformer,
				opcInformer:    opcInformer,
			},
		},
		// We want to be notified when a OPC's secret gets updated or deleted. When this happens, we
		// should get notified via the corresponding OPC key.
		withInformer(
			secretInformer,
			controllerlib.FilterFuncs{
				ParentFunc: func(obj metav1.Object) controllerlib.Key {
					if isOPCControllee(obj) {
						controller := metav1.GetControllerOf(obj)
						return controllerlib.Key{
							Name:      controller.Name,
							Namespace: obj.GetNamespace(),
						}
					}
					return controllerlib.Key{}
				},
				AddFunc: isOPCControllee,
				UpdateFunc: func(oldObj, newObj metav1.Object) bool {
					return isOPCControllee(oldObj) || isOPCControllee(newObj)
				},
				DeleteFunc: isOPCControllee,
			},
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
	opc, err := c.opcInformer.Lister().OIDCProviders(ctx.Key.Namespace).Get(ctx.Key.Name)
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
		// The corresponding secret to this OPC should have been garbage collected since it should have
		// had this OPC as its owner.
		plog.Debug(
			"oidcprovider deleted",
			"oidcprovider",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	secretNeedsUpdate, err := c.secretNeedsUpdate(opc)
	if err != nil {
		return fmt.Errorf("cannot determine secret status: %w", err)
	}
	if !secretNeedsUpdate {
		// Secret is up to date - we are good to go.
		plog.Debug(
			"secret is up to date",
			"oidcprovider",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	// If the OPC does not have a secret associated with it, that secret does not exist, or the secret
	// is invalid, we will generate a new secret (i.e., a JWKS).
	secret, err := generateSecret(opc.Namespace, c.secretNameFunc(opc), c.secretDataFunc, opc)
	if err != nil {
		return fmt.Errorf("cannot generate secret: %w", err)
	}

	if err := c.createOrUpdateSecret(ctx.Context, secret); err != nil {
		return fmt.Errorf("cannot create or update secret: %w", err)
	}
	plog.Debug("created/updated secret", "secret", klog.KObj(secret))

	return nil
}

func (c *oidcProviderSecretsController) secretNeedsUpdate(opc *configv1alpha1.OIDCProvider) (bool, error) {
	// This OPC says it has a secret associated with it. Let's try to get it from the cache.
	secret, err := c.secretInformer.Lister().Secrets(opc.Namespace).Get(c.secretNameFunc(opc))
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return false, fmt.Errorf("cannot get secret: %w", err)
	}
	if notFound {
		// If we can't find the secret, let's assume we need to create it.
		return true, nil
	}

	if !isValid(secret) {
		// If this secret is invalid, we need to generate a new one.
		return true, nil
	}

	return false, nil
}

func (c *oidcProviderSecretsController) createOrUpdateSecret(
	ctx context.Context,
	newSecret *corev1.Secret,
) error {
	secretClient := c.kubeClient.CoreV1().Secrets(newSecret.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldSecret, err := secretClient.Get(ctx, newSecret.Name, metav1.GetOptions{})
		notFound := k8serrors.IsNotFound(err)
		if err != nil && !notFound {
			return fmt.Errorf("cannot get secret: %w", err)
		}

		if notFound {
			// New secret doesn't exist, so create it.
			_, err := secretClient.Create(ctx, newSecret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("cannot create secret: %w", err)
			}
			return nil
		}

		// New secret already exists, so ensure it is up to date.
		if isValid(oldSecret) {
			// If the secret already has valid JWK's, then we are good to go and we don't need an update.
			return nil
		}

		oldSecret.Data = newSecret.Data
		_, err = secretClient.Update(ctx, oldSecret, metav1.UpdateOptions{})
		return err
	})
}

// isOPCControlle returns whether the provided obj is controlled by an OPC.
func isOPCControllee(obj metav1.Object) bool { // TODO: deduplicate - internal/controller/supervisorconfig/jwks_writer.go
	controller := metav1.GetControllerOf(obj)
	return controller != nil &&
		controller.APIVersion == configv1alpha1.SchemeGroupVersion.String() &&
		controller.Kind == opcKind
}
