/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package apicerts

import (
	"crypto/x509/pkix"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/suzerain-io/controller-go"
	"github.com/suzerain-io/placeholder-name/internal/autoregistration"
	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	placeholdernamecontroller "github.com/suzerain-io/placeholder-name/internal/controller"
)

const (
	//nolint: gosec
	certsSecretName              = "api-serving-cert"
	caCertificateSecretKey       = "caCertificate"
	tlsPrivateKeySecretKey       = "tlsPrivateKey"
	tlsCertificateChainSecretKey = "tlsCertificateChain"
)

type certsManagerController struct {
	namespace        string
	k8sClient        kubernetes.Interface
	aggregatorClient aggregatorclient.Interface
	secretInformer   corev1informers.SecretInformer
}

func NewCertsManagerController(
	namespace string,
	k8sClient kubernetes.Interface,
	aggregatorClient aggregatorclient.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer placeholdernamecontroller.WithInformerOptionFunc,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "certs-manager-controller",
			Syncer: &certsManagerController{
				namespace:        namespace,
				k8sClient:        k8sClient,
				aggregatorClient: aggregatorClient,
				secretInformer:   secretInformer,
			},
		},
		withInformer(
			secretInformer,
			placeholdernamecontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretName, namespace),
			controller.InformerOption{},
		),
		// Be sure to run once even if the Secret that the informer is watching doesn't exist.
		controller.WithInitialEvent(controller.Key{
			Namespace: namespace,
			Name:      certsSecretName,
		}),
	)
}

func (c *certsManagerController) Sync(ctx controller.Context) error {
	// Try to get the secret from the informer cache.
	_, err := c.secretInformer.Lister().Secrets(c.namespace).Get(certsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, certsSecretName, err)
	}
	if !notFound {
		// The secret already exists, so nothing to do.
		return nil
	}

	// Create a CA.
	aggregatedAPIServerCA, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}

	// This string must match the name of the Service declared in the deployment yaml.
	const serviceName = "placeholder-name-api"

	// Using the CA from above, create a TLS server cert for the aggregated API server to use.
	aggregatedAPIServerTLSCert, err := aggregatedAPIServerCA.Issue(
		pkix.Name{CommonName: serviceName + "." + c.namespace + ".svc"},
		[]string{},
		24*365*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	// Write the CA's public key bundle and the serving certs to a secret.
	tlsPrivateKeyPEM, tlsCertChainPEM, err := certauthority.ToPEM(aggregatedAPIServerTLSCert)
	if err != nil {
		return fmt.Errorf("could not PEM encode serving certificate: %w", err)
	}
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      certsSecretName,
			Namespace: c.namespace,
		},
		StringData: map[string]string{
			caCertificateSecretKey:       string(aggregatedAPIServerCA.Bundle()),
			tlsPrivateKeySecretKey:       string(tlsPrivateKeyPEM),
			tlsCertificateChainSecretKey: string(tlsCertChainPEM),
		},
	}
	_, err = c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx.Context, &secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create secret: %w", err)
	}

	// Update the APIService to give it the new CA bundle.
	if err := autoregistration.UpdateAPIService(ctx.Context, c.aggregatorClient, aggregatedAPIServerCA.Bundle()); err != nil {
		return fmt.Errorf("could not update the API service: %w", err)
	}

	klog.Info("certsManagerController Sync successfully created secret and updated API service")
	return nil
}
