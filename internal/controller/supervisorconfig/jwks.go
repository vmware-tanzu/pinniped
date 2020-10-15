// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	configinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

// These constants are the keys in an OPC's Secret's Data map.
const (
	// activeJWKKey points to the current private key used for signing tokens.
	//
	// Note! The value for this key will contain private key material!
	activeJWKKey = "activeJWK"
	// jwksKey points to the current JWKS used to verify tokens.
	//
	// Note! The value for this key will contain only public key material!
	jwksKey = "jwks"
)

const (
	opcKind = "OIDCProviderConfig"
)

// generateKey is stubbed out for the purpose of testing. The default behavior is to generate an RSA key.
//nolint:gochecknoglobals
var generateKey func(r io.Reader, bits int) (interface{}, error) = generateRSAKey

func generateRSAKey(r io.Reader, bits int) (interface{}, error) {
	return rsa.GenerateKey(r, bits)
}

// jwkController holds the fields necessary for the JWKS controller to communicate with OPC's and
// secrets, both via a cache and via the API.
type jwksController struct {
	pinnipedClient pinnipedclientset.Interface
	kubeClient     kubernetes.Interface
	opcInformer    configinformers.OIDCProviderConfigInformer
	secretInformer corev1informers.SecretInformer
}

// NewJWKSController returns a controllerlib.Controller that ensures an OPC has a corresponding
// Secret that contains a valid active JWK and JWKS.
func NewJWKSController(
	kubeClient kubernetes.Interface,
	pinnipedClient pinnipedclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	opcInformer configinformers.OIDCProviderConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "JWKSController",
			Syncer: &jwksController{
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
			pinnipedcontroller.NoOpFilter(),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *jwksController) Sync(ctx controllerlib.Context) error {
	opc, err := c.opcInformer.Lister().OIDCProviderConfigs(ctx.Key.Namespace).Get(ctx.Key.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf(
			"failed to get %s/%s OIDCProviderConfig: %w",
			ctx.Key.Namespace,
			ctx.Key.Name,
			err,
		)
	}

	if notFound {
		// The corresponding secret to this OPC should have been garbage collected since it should have
		// had this OPC as its owner.
		klog.InfoS(
			"oidcproviderconfig deleted",
			"oidcproviderconfig",
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
		klog.InfoS(
			"secret is up to date",
			"oidcproviderconfig",
			klog.KRef(ctx.Key.Namespace, ctx.Key.Name),
		)
		return nil
	}

	// If the OPC does not have a secret associated with it, that secret does not exist, or the secret
	// is invalid, we will generate a new secret (i.e., a JWKS).
	secret, err := c.generateSecret(opc)
	if err != nil {
		return fmt.Errorf("cannot generate secret: %w", err)
	}

	if err := c.createOrUpdateSecret(ctx.Context, secret); err != nil {
		return fmt.Errorf("cannot create or update secret: %w", err)
	}
	klog.InfoS("created/updated secret", "secret", klog.KObj(secret))

	// Ensure that the OPC points to the secret.
	newOPC := opc.DeepCopy()
	newOPC.Status.JWKSSecret.Name = secret.Name
	if err := c.updateOPC(ctx.Context, newOPC); err != nil {
		return fmt.Errorf("cannot update opc: %w", err)
	}
	klog.InfoS("updated oidcproviderconfig", "oidcproviderconfig", klog.KObj(newOPC))

	return nil
}

func (c *jwksController) secretNeedsUpdate(opc *configv1alpha1.OIDCProviderConfig) (bool, error) {
	if opc.Status.JWKSSecret.Name == "" {
		// If the OPC says it doesn't have a secret associated with it, then let's create one.
		return true, nil
	}

	// This OPC says it has a secret associated with it. Let's try to get it from the cache.
	secret, err := c.secretInformer.Lister().Secrets(opc.Namespace).Get(opc.Status.JWKSSecret.Name)
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

func (c *jwksController) generateSecret(opc *configv1alpha1.OIDCProviderConfig) (*corev1.Secret, error) {
	// Note! This is where we could potentially add more handling of OPC spec fields which tell us how
	// this OIDC provider should sign and verify ID tokens (e.g., hardcoded token secret, gRPC
	// connection to KMS, etc).
	//
	// For now, we just generate an new RSA keypair and put that in the secret.

	key, err := generateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %w", err)
	}

	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     "some-key",
		Algorithm: "RS256",
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
			Name:      opc.Name + "-jwks",
			Namespace: opc.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(opc, schema.GroupVersionKind{
					Group:   configv1alpha1.SchemeGroupVersion.Group,
					Version: configv1alpha1.SchemeGroupVersion.Version,
					Kind:    opcKind,
				}),
			},
			// TODO: custom labels.
		},
		Data: map[string][]byte{
			activeJWKKey: jwkData,
			jwksKey:      jwksData,
		},
	}

	return &s, nil
}

func (c *jwksController) createOrUpdateSecret(
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

func (c *jwksController) updateOPC(
	ctx context.Context,
	newOPC *configv1alpha1.OIDCProviderConfig,
) error {
	opcClient := c.pinnipedClient.ConfigV1alpha1().OIDCProviderConfigs(newOPC.Namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		oldOPC, err := opcClient.Get(ctx, newOPC.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("cannot get opc: %w", err)
		}

		if newOPC.Status.JWKSSecret.Name == oldOPC.Status.JWKSSecret.Name {
			// If the existing OPC is up to date, we don't need to update it.
			return nil
		}

		oldOPC.Status.JWKSSecret.Name = newOPC.Status.JWKSSecret.Name
		_, err = opcClient.Update(ctx, oldOPC, metav1.UpdateOptions{})
		return err
	})
}

// isOPCControlle returns whether the provided obj is controlled by an OPC.
func isOPCControllee(obj metav1.Object) bool {
	controller := metav1.GetControllerOf(obj)
	return controller != nil &&
		controller.APIVersion == configv1alpha1.SchemeGroupVersion.String() &&
		controller.Kind == opcKind
}

// isValid returns whether the provided secret contains a valid active JWK and verification JWKS.
func isValid(secret *corev1.Secret) bool {
	jwkData, ok := secret.Data[activeJWKKey]
	if !ok {
		klog.InfoS("secret does not contain active jwk")
		return false
	}

	var activeJWK jose.JSONWebKey
	if err := json.Unmarshal(jwkData, &activeJWK); err != nil {
		klog.InfoS("cannot unmarshal active jwk", "err", err)
		return false
	}

	if activeJWK.IsPublic() {
		klog.InfoS("active jwk is public", "keyid", activeJWK.KeyID)
		return false
	}

	if !activeJWK.Valid() {
		klog.InfoS("active jwk is not valid", "keyid", activeJWK.KeyID)
		return false
	}

	jwksData, ok := secret.Data[jwksKey]
	if !ok {
		klog.InfoS("secret does not contain valid jwks")
	}

	var validJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(jwksData, &validJWKS); err != nil {
		klog.InfoS("cannot unmarshal valid jwks", "err", err)
		return false
	}

	foundActiveJWK := false
	for _, validJWK := range validJWKS.Keys {
		if !validJWK.IsPublic() {
			klog.InfoS("jwks key is not public", "keyid", validJWK.KeyID)
			return false
		}
		if !validJWK.Valid() {
			klog.InfoS("jwks key is not valid", "keyid", validJWK.KeyID)
			return false
		}
		if validJWK.KeyID == activeJWK.KeyID {
			foundActiveJWK = true
		}
	}

	if !foundActiveJWK {
		klog.InfoS("did not find active jwk in valid jwks", "keyid", activeJWK.KeyID)
		return false
	}

	return true
}
