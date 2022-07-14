// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

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
	secrets corev1client.SecretInterface
}

// StoredClientSecret defines the format of the content of a client's secrets when stored in a Secret
// as a JSON string value.
type StoredClientSecret struct {
	// List of bcrypt hashes.
	SecretHashes []string `json:"hashes"`
	// The format version. Take care when updating. We cannot simply bump the storage version and drop/ignore old data.
	// Updating this would require some form of migration of existing stored data.
	Version string `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time) *OIDCClientSecretStorage {
	return &OIDCClientSecretStorage{
		storage: crud.New(TypeLabelValue, secrets, clock, 0),
		secrets: secrets,
	}
}

// TODO expose other methods as needed for get, create, update, etc.

// GetStorageSecret gets the corev1.Secret which is used to store the client secrets for the given client.
// Returns nil,nil when the corev1.Secret was not found, as this is not an error for a client to not have any secrets yet.
func (s *OIDCClientSecretStorage) GetStorageSecret(ctx context.Context, oidcClientUID types.UID) (*corev1.Secret, error) {
	secret, err := s.secrets.Get(ctx, s.GetName(oidcClientUID), metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetName returns the name of the Secret which would be used to store data for the given signature.
func (s *OIDCClientSecretStorage) GetName(oidcClientUID types.UID) string {
	// Avoid having s.storage.GetName() base64 decode something that wasn't ever encoded by encoding it here.
	b64encodedUID := base64.RawURLEncoding.EncodeToString([]byte(oidcClientUID))
	return s.storage.GetName(b64encodedUID)
}

// ReadFromSecret reads the contents of a Secret as a StoredClientSecret.
func ReadFromSecret(secret *corev1.Secret) (*StoredClientSecret, error) {
	storedClientSecret := &StoredClientSecret{}
	err := crud.FromSecret(TypeLabelValue, secret, storedClientSecret)
	if err != nil {
		return nil, err
	}
	if storedClientSecret.Version != oidcClientSecretStorageVersion {
		return nil, fmt.Errorf("%w: OIDC client secret storage has version %s instead of %s",
			ErrOIDCClientSecretStorageVersion, storedClientSecret.Version, oidcClientSecretStorageVersion)
	}
	return storedClientSecret, nil
}
