// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"context"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
)

const (
	TypeLabelValue = "oidc-client-secret"

	ErrOIDCClientSecretStorageVersion = constable.Error("OIDC client secret storage data has wrong version")

	// Version 1 was the initial release of the OIDCClientSecretRequest API, which uses OIDCClientSecretStorage for storage.
	oidcClientSecretStorageVersion = "1"
)

type OIDCClientSecretStorage struct {
	storage crud.Storage
	secrets corev1client.SecretInterface
}

// storedClientSecret defines the format of the content of a client's secrets when stored in a Secret
// as a JSON string value.
type storedClientSecret struct {
	// List of bcrypt hashes.
	SecretHashes []string `json:"hashes"`
	// The format version. Take care when updating. We cannot simply bump the storage version and drop/ignore old data.
	// Updating this would require some form of migration of existing stored data.
	Version string `json:"version"`
}

func New(secrets corev1client.SecretInterface) *OIDCClientSecretStorage {
	return &OIDCClientSecretStorage{
		storage: crud.New(TypeLabelValue, secrets, nil), // can use nil clock because we are using infinite lifetime for creates
		secrets: secrets,
	}
}

// Get returns the resourceVersion of the storage secret, the hashes within the secret, and an error.
// When the storage secret is not found, it will simply return "", nil, nil to make it easy to pass the
// results of Get directly to Set.
func (s *OIDCClientSecretStorage) Get(ctx context.Context, oidcClientUID types.UID) (string, []string, error) {
	clientSecret := &storedClientSecret{}
	rv, err := s.storage.Get(ctx, uidToName(oidcClientUID), clientSecret)
	if apierrors.IsNotFound(err) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to get client secret for uid %s: %w", oidcClientUID, err)
	}
	if clientSecret.Version != oidcClientSecretStorageVersion {
		return "", nil, fmt.Errorf("%w: OIDC client secret storage has version %s instead of %s",
			ErrOIDCClientSecretStorageVersion, clientSecret.Version, oidcClientSecretStorageVersion)
	}
	return rv, clientSecret.SecretHashes, nil
}

// Set will create or update the values of the storage secret associated with an OIDCClient.
// Set takes the resourceVersion to know if we are doing a create or update and to ensure we do not edit an old version of the storage secret.
// Set takes the oidcClientName to set up the owner reference of the storage secret to that of the OIDCClient.
// Set takes the oidcClientUID to find the correct storage secret.
func (s *OIDCClientSecretStorage) Set(ctx context.Context, resourceVersion, oidcClientName string, oidcClientUID types.UID, secretHashes []string) error {
	secret := &storedClientSecret{
		SecretHashes: secretHashes,
		Version:      oidcClientSecretStorageVersion,
	}
	name := uidToName(oidcClientUID)

	if mustBeCreate := len(resourceVersion) == 0; mustBeCreate {
		// Setup an owner reference for garbage collection purposes. When the OIDCClient is deleted, then this
		// corresponding client secret storage secret should also be automatically deleted (by Kube garbage collection).
		ownerReferences := []metav1.OwnerReference{{
			APIVersion:         configv1alpha1.SchemeGroupVersion.String(),
			Kind:               "OIDCClient",
			Name:               oidcClientName,
			UID:                oidcClientUID,
			Controller:         nil, // doesn't seem to matter, and there is no particular controller owning this
			BlockOwnerDeletion: nil,
		}}
		if _, err := s.storage.Create(ctx, name, secret, nil, ownerReferences, 0); err != nil { // 0 is infinite lifetime
			return fmt.Errorf("failed to create client secret for uid %s: %w", oidcClientUID, err)
		}
		return nil
	}

	if _, err := s.storage.Update(ctx, name, resourceVersion, secret); err != nil {
		return fmt.Errorf("failed to update client secret for uid %s: %w", oidcClientUID, err)
	}
	return nil
}

// GetStorageSecret gets the corev1.Secret which is used to store the client secrets for the given client.
// Returns nil,nil when the corev1.Secret was not found, as this is not an error for a client to not have any secrets yet.
func (s *OIDCClientSecretStorage) GetStorageSecret(ctx context.Context, oidcClientUID types.UID) (*corev1.Secret, error) {
	secret, err := s.secrets.Get(ctx, s.GetName(oidcClientUID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetName returns the name of the Secret which would be used to store data for the given signature.
func (s *OIDCClientSecretStorage) GetName(oidcClientUID types.UID) string {
	return s.storage.GetName(uidToName(oidcClientUID))
}

func uidToName(oidcClientUID types.UID) string {
	// Avoid having s.storage.GetName() base64 decode something that wasn't ever encoded by encoding it here.
	return base64.RawURLEncoding.EncodeToString([]byte(oidcClientUID))
}

// ReadFromSecret reads the contents of a Secret as a storedClientSecret and returns the associated hashes.
func ReadFromSecret(secret *corev1.Secret) ([]string, error) {
	clientSecret := &storedClientSecret{}
	err := crud.FromSecret(TypeLabelValue, secret, clientSecret)
	if err != nil {
		return nil, err
	}
	if clientSecret.Version != oidcClientSecretStorageVersion {
		return nil, fmt.Errorf("%w: OIDC client secret storage has version %s instead of %s",
			ErrOIDCClientSecretStorageVersion, clientSecret.Version, oidcClientSecretStorageVersion)
	}
	return clientSecret.SecretHashes, nil
}
