// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"context"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

	oidcClientSecretStorageVersion = "1"
)

type OIDCClientSecretStorage struct {
	storage crud.Storage
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
	return &OIDCClientSecretStorage{storage: crud.New(TypeLabelValue, secrets, nil, 0)}
}

func (s *OIDCClientSecretStorage) Get(ctx context.Context, oidcClientUID types.UID) (string, []string, error) {
	secret := &storedClientSecret{}
	rv, err := s.storage.Get(ctx, uidToName(oidcClientUID), secret)
	if errors.IsNotFound(err) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to get client secret for uid %s: %w", oidcClientUID, err)
	}

	return rv, secret.SecretHashes, nil
}

func (s *OIDCClientSecretStorage) Set(ctx context.Context, resourceVersion, oidcClientName string, oidcClientUID types.UID, secretHashes []string) error {
	secret := &storedClientSecret{
		SecretHashes: secretHashes,
		Version:      oidcClientSecretStorageVersion,
	}
	name := uidToName(oidcClientUID)

	if mustBeCreate := len(resourceVersion) == 0; mustBeCreate {
		ownerReferences := []metav1.OwnerReference{
			{
				APIVersion:         configv1alpha1.SchemeGroupVersion.String(),
				Kind:               "OIDCClient",
				Name:               oidcClientName,
				UID:                oidcClientUID,
				Controller:         nil, // TODO should this be true?
				BlockOwnerDeletion: nil,
			},
		}
		if _, err := s.storage.Create(ctx, name, secret, nil, ownerReferences); err != nil {
			return fmt.Errorf("failed to create client secret for uid %s: %w", oidcClientUID, err)
		}
		return nil
	}

	if _, err := s.storage.Update(ctx, name, resourceVersion, secret); err != nil {
		return fmt.Errorf("failed to update client secret for uid %s: %w", oidcClientUID, err)
	}
	return nil
}

// GetName returns the name of the Secret which would be used to store data for the given signature.
func (s *OIDCClientSecretStorage) GetName(oidcClientUID types.UID) string {
	return s.storage.GetName(uidToName(oidcClientUID))
}

func uidToName(oidcClientUID types.UID) string {
	// Avoid having s.storage.GetName() base64 decode something that wasn't ever encoded by encoding it here.
	return base64.RawURLEncoding.EncodeToString([]byte(oidcClientUID))
}

// ReadFromSecret reads the contents of a Secret as a storedClientSecret.
func ReadFromSecret(s *corev1.Secret) (*storedClientSecret, error) {
	secret := &storedClientSecret{}
	err := crud.FromSecret(TypeLabelValue, s, secret)
	if err != nil {
		return nil, err
	}
	if secret.Version != oidcClientSecretStorageVersion {
		return nil, fmt.Errorf("%w: OIDC client secret storage has version %s instead of %s",
			ErrOIDCClientSecretStorageVersion, secret.Version, oidcClientSecretStorageVersion)
	}
	return secret, nil
}
