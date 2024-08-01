// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/internal/certauthority"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

// The following key names are unexported, to prevent a leaky abstraction.
// Even the string literals should only be used in a very limited set of places:
// - The unit tests for this file
// - The unit tests for retrieve_from_secret.go
// - Integration tests
// Comment must end in a period, so here's a period: .
const (
	caCertificateSecretKey           = "caCertificate"
	caCertificatePrivateKeySecretKey = "caCertificatePrivateKey"
	tlsCertificateChainSecretKey     = "tlsCertificateChain"
	tlsPrivateKeySecretKey           = "tlsPrivateKey"
)

type certsCreatorController struct {
	namespace               string
	certsSecretResourceName string
	certsSecretLabels       map[string]string
	k8sClient               kubernetes.Interface
	secretInformer          corev1informers.SecretInformer

	// certDuration is the lifetime of both the serving certificate and its CA
	// certificate that this controller will use when issuing the certificates.
	certDuration time.Duration

	generatedCACommonName                 string
	serviceNameForGeneratedCertCommonName string
}

func NewCertsCreatorController(
	namespace string,
	certsSecretResourceName string,
	certsSecretLabels map[string]string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	withInitialEvent pinnipedcontroller.WithInitialEventOptionFunc,
	certDuration time.Duration,
	generatedCACommonName string,
	serviceNameForGeneratedCertCommonName string,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "certs-creator-controller",
			Syncer: &certsCreatorController{
				namespace:                             namespace,
				certsSecretResourceName:               certsSecretResourceName,
				certsSecretLabels:                     certsSecretLabels,
				k8sClient:                             k8sClient,
				secretInformer:                        secretInformer,
				certDuration:                          certDuration,
				generatedCACommonName:                 generatedCACommonName,
				serviceNameForGeneratedCertCommonName: serviceNameForGeneratedCertCommonName,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretResourceName, namespace),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even if the Secret that the informer is watching doesn't exist.
		withInitialEvent(controllerlib.Key{
			Namespace: namespace,
			Name:      certsSecretResourceName,
		}),
	)
}

func (c *certsCreatorController) Sync(ctx controllerlib.Context) error {
	// Try to get the secret from the informer cache.
	_, err := c.secretInformer.Lister().Secrets(c.namespace).Get(c.certsSecretResourceName)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, c.certsSecretResourceName, err)
	}
	if !notFound {
		// The secret already exists, so nothing to do.
		return nil
	}

	// Create a CA.
	ca, err := certauthority.New(c.generatedCACommonName, c.certDuration)
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}

	caPrivateKeyPEM, err := ca.PrivateKeyToPEM()
	if err != nil {
		return fmt.Errorf("could not get CA private key: %w", err)
	}

	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.certsSecretResourceName,
			Namespace: c.namespace,
			Labels:    c.certsSecretLabels,
		},
		Data: map[string][]byte{
			caCertificateSecretKey:           ca.Bundle(),
			caCertificatePrivateKeySecretKey: caPrivateKeyPEM,
		},
	}

	// Using the CA from above, create a TLS server cert if we have service name.
	if len(c.serviceNameForGeneratedCertCommonName) != 0 {
		serviceEndpoint := c.serviceNameForGeneratedCertCommonName + "." + c.namespace + ".svc"
		// Allow clients to use either service-name.namespace.svc or service-name.namespace.svc.cluster.local to verify TLS.
		tlsCert, err := ca.IssueServerCert([]string{serviceEndpoint, serviceEndpoint + ".cluster.local"}, nil, c.certDuration)
		if err != nil {
			return fmt.Errorf("could not issue serving certificate: %w", err)
		}

		// Write the CA's public key bundle and the serving certs to a secret.
		tlsCertChainPEM, tlsPrivateKeyPEM, err := certauthority.ToPEM(tlsCert)
		if err != nil {
			return fmt.Errorf("could not PEM encode serving certificate: %w", err)
		}

		secret.Data[tlsPrivateKeySecretKey] = tlsPrivateKeyPEM
		secret.Data[tlsCertificateChainSecretKey] = tlsCertChainPEM
	}

	_, err = c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx.Context, &secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create secret: %w", err)
	}

	plog.Info("certsCreatorController Sync successfully created secret")
	return nil
}
