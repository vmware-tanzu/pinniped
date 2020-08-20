/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

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

	"github.com/suzerain-io/controller-go"
	"github.com/suzerain-io/placeholder-name/internal/constable"
	placeholdernamecontroller "github.com/suzerain-io/placeholder-name/internal/controller"
)

type certsExpirerController struct {
	namespace      string
	k8sClient      kubernetes.Interface
	secretInformer corev1informers.SecretInformer

	// ageThreshold is a percentage (i.e., a real number between 0 and 1,
	// inclusive) indicating the point in a certificate's lifetime where this
	// controller will start to try to rotate it.
	//
	// Said another way, once ageThreshold % of a certificate's lifetime has
	// passed, this controller will try to delete it to force a new certificate
	// to be created.
	ageThreshold float32
}

// NewCertsExpirerController returns a controller.Controller that will delete a
// CA once it gets within some threshold of its expiration time.
func NewCertsExpirerController(
	namespace string,
	k8sClient kubernetes.Interface,
	secretInformer corev1informers.SecretInformer,
	withInformer placeholdernamecontroller.WithInformerOptionFunc,
	ageThreshold float32,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "certs-expirer-controller",
			Syncer: &certsExpirerController{
				namespace:      namespace,
				k8sClient:      k8sClient,
				secretInformer: secretInformer,
				ageThreshold:   ageThreshold,
			},
		},
		withInformer(
			secretInformer,
			placeholdernamecontroller.NameAndNamespaceExactMatchFilterFactory(certsSecretName, namespace),
			controller.InformerOption{},
		),
	)
}

// Sync implements controller.Syncer.Sync.
func (c *certsExpirerController) Sync(ctx controller.Context) error {
	secret, err := c.secretInformer.Lister().Secrets(c.namespace).Get(certsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s secret: %w", c.namespace, certsSecretName, err)
	}
	if notFound {
		klog.Info("certsExpirerController Sync() found that the secret does not exist yet or was deleted")
		return nil
	}

	notBefore, notAfter, err := getCABounds(secret)
	if err != nil {
		// If we can't get the CA, then really all we can do is log something, since
		// if we returned an error then the controller lib would just call us again
		// and again, which would probably yield the same results.
		klog.Warningf("certsExpirerController Sync() found that the secret is malformed: %s", err.Error())
		return nil
	}

	caLifetime := notAfter.Sub(notBefore)
	caAge := time.Since(notBefore)
	thresholdDelta := (float32(caAge) / float32(caLifetime)) - c.ageThreshold
	klog.Infof("certsExpirerController Sync() found a CA age threshold delta of %.2f", thresholdDelta)
	if thresholdDelta > 0 {
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

// getCABounds returns the NotBefore and NotAfter fields of the CA certificate
// in the provided secret, or an error. Not that it expects the provided secret
// to contain the well-known data keys from this package (see certs_manager.go).
func getCABounds(secret *corev1.Secret) (time.Time, time.Time, error) {
	caPEM := secret.Data[caCertificateSecretKey]
	if caPEM == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to find CA")
	}

	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return time.Time{}, time.Time{}, constable.Error("failed to decode CA PEM")
	}

	caCrt, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("failed to parse CA: %w", err)
	}

	return caCrt.NotBefore, caCrt.NotAfter, nil
}
