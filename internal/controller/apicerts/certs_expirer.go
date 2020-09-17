// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/pinniped/internal/constable"
	pinnipedcontroller "github.com/vmware-tanzu/pinniped/internal/controller"
	"github.com/vmware-tanzu/pinniped/internal/controllerlib"
)

type certsExpirerController struct {
	namespace      string
	k8sClient      kubernetes.Interface
	secretInformer corev1informers.SecretInformer

	// renewBefore is the amount of time after the cert's issuance where
	// this controller will start to try to rotate it.
	renewBefore time.Duration
}

// NewCertsExpirerController returns a controllerlib.Controller that will delete a
// certificate secret once it gets within some threshold of its expiration time. The
// deletion forces rotation of the secret with the help of other controllers.
func NewCertsExpirerController(
	namespace string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	renewBefore time.Duration,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "certs-expirer-controller",
			Syncer: &certsExpirerController{
				namespace:      namespace,
				k8sClient:      k8sClient,
				secretInformer: secretInformer,
				renewBefore:    renewBefore,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretName, namespace),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controller.Syncer.Sync.
func (c *certsExpirerController) Sync(ctx controllerlib.Context) error {
	secret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(certsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, certsSecretName, err)
	}
	if notFound {
		klog.Info("certsExpirerController Sync found that the secret does not exist yet or was deleted")
		return nil
	}

	notBefore, notAfter, err := getCertBounds(secret)
	if err != nil {
		// If we can't read the cert, then really all we can do is log something,
		// since if we returned an error then the controller lib would just call us
		// again and again, which would probably yield the same results.
		klog.Warningf("certsExpirerController Sync found that the secret is malformed: %s", err.Error())
		return nil
	}

	certAge := time.Since(notBefore)
	renewDelta := certAge - c.renewBefore
	klog.Infof("certsExpirerController Sync found a renew delta of %s", renewDelta)
	if renewDelta >= 0 || time.Now().After(notAfter) {
		err := c.k8sClient.
			CoreV1().
			Secrets(c.namespace).
			Delete(ctx.Context, certsSecretName, metav1.DeleteOptions{})
		if err != nil {
			// Do return an error here so that the controller library will reschedule
			// us to try deleting this cert again.
			return err
		}
	}

	return nil
}

// getCertBounds returns the NotBefore and NotAfter fields of the TLS
// certificate in the provided secret, or an error. Not that it expects the
// provided secret to contain the well-known data keys from this package (see
// certs_manager.go).
func getCertBounds(secret *corev1.Secret) (time.Time, time.Time, error) {
	certPEM := secret.Data[tlsCertificateChainSecretKey]
	if certPEM == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to find certificate")
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotBefore, cert.NotAfter, nil
}
