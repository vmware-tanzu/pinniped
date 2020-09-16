// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
)

type apiServiceUpdaterController struct {
	namespace        string
	aggregatorClient aggregatorclient.Interface
	secretInformer   corev1informers.SecretInformer
	apiServiceName   string
}

func NewAPIServiceUpdaterController(
	namespace string,
	apiServiceName string,
	aggregatorClient aggregatorclient.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "certs-manager-controller",
			Syncer: &apiServiceUpdaterController{
				namespace:        namespace,
				aggregatorClient: aggregatorClient,
				secretInformer:   secretInformer,
				apiServiceName:   apiServiceName,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretName, namespace),
			controllerlib.InformerOption{},
		),
	)
}

func (c *apiServiceUpdaterController) Sync(ctx controllerlib.Context) error {
	// Try to get the secret from the informer cache.
	certSecret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(certsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, certsSecretName, err)
	}
	if notFound {
		// The secret does not exist yet, so nothing to do.
		klog.Info("apiServiceUpdaterController Sync found that the secret does not exist yet or was deleted")
		return nil
	}

	// Update the APIService to give it the new CA bundle.
	if err := UpdateAPIService(ctx.Context, c.aggregatorClient, c.apiServiceName, certSecret.Data[caCertificateSecretKey]); err != nil {
		return fmt.Errorf("could not update the API service: %w", err)
	}

	klog.Info("apiServiceUpdaterController Sync successfully updated API service")
	return nil
}
