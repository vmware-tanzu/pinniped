// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

type apiServiceUpdaterController struct {
	namespace               string
	certsSecretResourceName string
	aggregatorClient        aggregatorclient.Interface
	secretInformer          corev1informers.SecretInformer
	apiServiceName          string
}

func NewAPIServiceUpdaterController(
	namespace string,
	certsSecretResourceName string,
	apiServiceName string,
	aggregatorClient aggregatorclient.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "api-service-updater-controller",
			Syncer: &apiServiceUpdaterController{
				namespace:               namespace,
				certsSecretResourceName: certsSecretResourceName,
				aggregatorClient:        aggregatorClient,
				secretInformer:          secretInformer,
				apiServiceName:          apiServiceName,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretResourceName, namespace),
			controllerlib.InformerOption{},
		),
	)
}

func (c *apiServiceUpdaterController) Sync(ctx controllerlib.Context) error {
	// Try to get the secret from the informer cache.
	certSecret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(c.certsSecretResourceName)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, c.certsSecretResourceName, err)
	}
	if notFound {
		// The secret does not exist yet, so nothing to do.
		plog.Info("apiServiceUpdaterController Sync found that the secret does not exist yet or was deleted")
		return nil
	}

	// Update the APIService to give it the new CA bundle.
	if err := UpdateAPIService(
		ctx.Context,
		c.aggregatorClient,
		c.apiServiceName,
		c.namespace,
		certSecret.Data[CACertificateSecretKey],
	); err != nil {
		return fmt.Errorf("could not update the API service: %w", err)
	}

	plog.Debug("apiServiceUpdaterController Sync complete")
	return nil
}
