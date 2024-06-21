// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/supervisorconfig/generator"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

// These constants are the keys in a FederationDomain's Secret's Data map.
const (
	// activeJWKKey points to the current private key used for signing tokens.
	//
	// Note! The value for this key will contain private key material!
	activeJWKKey = "activeJWK"
	// jwksKey points to the current JWKS used to verify tokens.
	//
	// Note! The value for this key will contain only public key material!
	jwksKey = "jwks"

	jwksSecretTypeValue corev1.SecretType = "secrets.pinniped.dev/federation-domain-jwks"
)

const (
	federationDomainKind = "FederationDomain"
)

// generateKey is stubbed out for the purpose of testing. The default behavior is to generate an EC key.
var generateKey = generateECKey //nolint:gochecknoglobals

func generateECKey(r io.Reader) (any, error) {
	return ecdsa.GenerateKey(elliptic.P256(), r)
}

// jwkController holds the fields necessary for the JWKS controller to communicate with FederationDomains and
// secrets, both via a cache and via the API.
type jwksWriterController struct {
	jwksSecretLabels         map[string]string
	pinnipedClient           supervisorclientset.Interface
	kubeClient               kubernetes.Interface
	federationDomainInformer configinformers.FederationDomainInformer
	secretInformer           corev1informers.SecretInformer
}

// NewJWKSWriterController returns a controllerlib.Controller that ensures a FederationDomain has a corresponding
// Secret that contains a valid active JWK and JWKS.
func NewJWKSWriterController(
	jwksSecretLabels map[string]string,
	kubeClient kubernetes.Interface,
	pinnipedClient supervisorclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	federationDomainInformer configinformers.FederationDomainInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	isSecretToSync := func(obj metav1.Object) bool {
		return generator.IsFederationDomainSecretOfType(obj, jwksSecretTypeValue)
	}

	return controllerlib.New(
		controllerlib.Config{
			Name: "JWKSController",
			Syncer: &jwksWriterController{
				jwksSecretLabels:         jwksSecretLabels,
				kubeClient:               kubeClient,
				pinnipedClient:           pinnipedClient,
				secretInformer:           secretInformer,
				federationDomainInformer: federationDomainInformer,
			},
		},
		// We want to be notified when a FederationDomain's secret gets updated or deleted. When this happens, we
		// should get notified via the corresponding FederationDomain key.
		withInformer(
			secretInformer,
			pinnipedcontroller.SimpleFilter(isSecretToSync, pinnipedcontroller.SecretIsControlledByParentFunc(isSecretToSync)),
			controllerlib.InformerOption{},
		),
		// We want to be notified when anything happens to an FederationDomain.
		withInformer(
			federationDomainInformer,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *jwksWriterController) Sync(ctx controllerlib.Context) error {
	federationDomain, err := c.federationDomainInformer.Lister().FederationDomains(ctx.Key.Namespace).Get(ctx.Key.Name)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf(
			"failed to get %s/%s FederationDomain: %w",
			ctx.Key.Namespace,
			ctx.Key.Name,
			err,
		)
	}

	if notFound {
		// The corresponding secret to this FederationDomain should have been garbage collected since it should have
		// had this FederationDomain as its owner.
		plog.Debug(
			"FederationDomain deleted",
			"federationdomain",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	secretNeedsUpdate, err := c.secretNeedsUpdate(federationDomain)
	if err != nil {
		return fmt.Errorf("cannot determine secret status: %w", err)
	}
	if !secretNeedsUpdate {
		// Secret is up to date - we are good to go.
		plog.Debug(
			"secret is up to date",
			"federationdomain",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	// If the FederationDomain does not have a secret associated with it, that secret does not exist, or the secret
	// is invalid, we will generate a new secret (i.e., a JWKS).
	secret, err := c.generateSecret(federationDomain)
	if err != nil {
		return fmt.Errorf("cannot generate secret: %w", err)
	}

	if err := c.createOrUpdateSecret(ctx.Context, secret); err != nil {
		return fmt.Errorf("cannot create or update secret: %w", err)
	}
	plog.Debug("created/updated secret", "secret", klog.KObj(secret))

	// Ensure that the FederationDomain points to the secret.
	newFederationDomain := federationDomain.DeepCopy()
	newFederationDomain.Status.Secrets.JWKS.Name = secret.Name
	if err := c.updateFederationDomainStatus(ctx.Context, newFederationDomain); err != nil {
		return fmt.Errorf("cannot update FederationDomain: %w", err)
	}
	plog.Debug("updated FederationDomain", "federationdomain", klog.KObj(newFederationDomain))

	return nil
}

func (c *jwksWriterController) secretNeedsUpdate(federationDomain *supervisorconfigv1alpha1.FederationDomain) (bool, error) {
	if federationDomain.Status.Secrets.JWKS.Name == "" {
		// If the FederationDomain says it doesn't have a secret associated with it, then let's create one.
		return true, nil
	}

	// This FederationDomain says it has a secret associated with it. Let's try to get it from the cache.
	secret, err := c.secretInformer.Lister().Secrets(federationDomain.Namespace).Get(federationDomain.Status.Secrets.JWKS.Name)
	notFound := apierrors.IsNotFound(err)
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

func (c *jwksWriterController) generateSecret(federationDomain *supervisorconfigv1alpha1.FederationDomain) (*corev1.Secret, error) {
	// Note! This is where we could potentially add more handling of FederationDomain spec fields which tell us how
	// this FederationDomain should sign and verify ID tokens (e.g., hardcoded token secret, gRPC
	// connection to KMS, etc).
	//
	// For now, we just generate an new RSA keypair and put that in the secret.

	key, err := generateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %w", err)
	}

	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     "pinniped-supervisor-key",
		Algorithm: "ES256",
		Use:       "sig",
	}
	jwkData, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal jwk: %w", err)
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk.Public()},
	}
	jwksData, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal jwks: %w", err)
	}

	s := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      federationDomain.Name + "-jwks",
			Namespace: federationDomain.Namespace,
			Labels:    c.jwksSecretLabels,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(federationDomain, schema.GroupVersionKind{
					Group:   supervisorconfigv1alpha1.SchemeGroupVersion.Group,
					Version: supervisorconfigv1alpha1.SchemeGroupVersion.Version,
					Kind:    federationDomainKind,
				}),
			},
		},
		Data: map[string][]byte{
			activeJWKKey: jwkData,
			jwksKey:      jwksData,
		},
		Type: jwksSecretTypeValue,
	}

	return &s, nil
}

func (c *jwksWriterController) createOrUpdateSecret(
	ctx context.Context,
	newSecret *corev1.Secret,
) error {
	secretClient := c.kubeClient.CoreV1().Secrets(newSecret.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldSecret, err := secretClient.Get(ctx, newSecret.Name, metav1.GetOptions{})
		notFound := apierrors.IsNotFound(err)
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
		oldSecret.Type = jwksSecretTypeValue
		_, err = secretClient.Update(ctx, oldSecret, metav1.UpdateOptions{})
		return err
	})
}

func (c *jwksWriterController) updateFederationDomainStatus(
	ctx context.Context,
	newFederationDomain *supervisorconfigv1alpha1.FederationDomain,
) error {
	federationDomainClient := c.pinnipedClient.ConfigV1alpha1().FederationDomains(newFederationDomain.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldFederationDomain, err := federationDomainClient.Get(ctx, newFederationDomain.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("cannot get FederationDomain: %w", err)
		}

		if newFederationDomain.Status.Secrets.JWKS.Name == oldFederationDomain.Status.Secrets.JWKS.Name {
			// If the existing FederationDomain is up to date, we don't need to update it.
			return nil
		}

		oldFederationDomain.Status.Secrets.JWKS.Name = newFederationDomain.Status.Secrets.JWKS.Name
		_, err = federationDomainClient.UpdateStatus(ctx, oldFederationDomain, metav1.UpdateOptions{})
		return err
	})
}

// isValid returns whether the provided secret contains a valid active JWK and verification JWKS.
func isValid(secret *corev1.Secret) bool {
	if secret.Type != jwksSecretTypeValue {
		plog.Debug("secret does not have the expected type", "expectedType", jwksSecretTypeValue, "actualType", secret.Type)
		return false
	}

	jwkData, ok := secret.Data[activeJWKKey]
	if !ok {
		plog.Debug("secret does not contain active jwk")
		return false
	}

	var activeJWK jose.JSONWebKey
	if err := json.Unmarshal(jwkData, &activeJWK); err != nil {
		plog.Debug("cannot unmarshal active jwk", "err", err)
		return false
	}

	if activeJWK.IsPublic() {
		plog.Debug("active jwk is public", "keyid", activeJWK.KeyID)
		return false
	}

	if !activeJWK.Valid() {
		plog.Debug("active jwk is not valid", "keyid", activeJWK.KeyID)
		return false
	}

	jwksData, ok := secret.Data[jwksKey]
	if !ok {
		plog.Debug("secret does not contain valid jwks")
	}

	var validJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(jwksData, &validJWKS); err != nil {
		plog.Debug("cannot unmarshal valid jwks", "err", err)
		return false
	}

	foundActiveJWK := false
	for _, validJWK := range validJWKS.Keys {
		if !validJWK.IsPublic() {
			plog.Debug("jwks key is not public", "keyid", validJWK.KeyID)
			return false
		}
		if !validJWK.Valid() {
			plog.Debug("jwks key is not valid", "keyid", validJWK.KeyID)
			return false
		}
		if validJWK.KeyID == activeJWK.KeyID {
			foundActiveJWK = true
		}
	}

	if !foundActiveJWK {
		plog.Debug("did not find active jwk in valid jwks", "keyid", activeJWK.KeyID)
		return false
	}

	return true
}
