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

	"github.com/suzerain-io/pinniped/internal/certauthority"
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
)

const (
	//nolint: gosec
	certsSecretName              = "api-serving-cert"
	caCertificateSecretKey       = "caCertificate"
	tlsPrivateKeySecretKey       = "tlsPrivateKey"
	tlsCertificateChainSecretKey = "tlsCertificateChain"
)

type certsManagerController struct {
	namespace      string
	k8sClient      kubernetes.Interface
	secretInformer corev1informers.SecretInformer

	// certDuration is the lifetime of both the serving certificate and its CA
	// certificate that this controller will use when issuing the certificates.
	certDuration time.Duration

	generatedCACommonName                 string
	serviceNameForGeneratedCertCommonName string
}

func NewCertsManagerController(namespace string,
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
			Name: "certs-manager-controller",
			Syncer: &certsManagerController{
				namespace:                             namespace,
				k8sClient:                             k8sClient,
				secretInformer:                        secretInformer,
				certDuration:                          certDuration,
				generatedCACommonName:                 generatedCACommonName,
				serviceNameForGeneratedCertCommonName: serviceNameForGeneratedCertCommonName,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretName, namespace),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even if the Secret that the informer is watching doesn't exist.
		withInitialEvent(controllerlib.Key{
			Namespace: namespace,
			Name:      certsSecretName,
		}),
	)
}

func (c *certsManagerController) Sync(ctx controllerlib.Context) error {
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
	aggregatedAPIServerCA, err := certauthority.New(pkix.Name{CommonName: c.generatedCACommonName}, c.certDuration)
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}

	// Using the CA from above, create a TLS server cert for the aggregated API server to use.
	serviceEndpoint := c.serviceNameForGeneratedCertCommonName + "." + c.namespace + ".svc"
	aggregatedAPIServerTLSCert, err := aggregatedAPIServerCA.Issue(
		pkix.Name{CommonName: serviceEndpoint},
		[]string{serviceEndpoint},
		c.certDuration,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	// Write the CA's public key bundle and the serving certs to a secret.
	tlsCertChainPEM, tlsPrivateKeyPEM, err := certauthority.ToPEM(aggregatedAPIServerTLSCert)
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

	klog.Info("certsManagerController Sync successfully created secret")
	return nil
}
