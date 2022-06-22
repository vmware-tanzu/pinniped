// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientsecretstorage

import (
	"encoding/base64"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
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
	// TODO make lifetime = 0 mean that it does not get annotated with any garbage collection annotation
	return &OIDCClientSecretStorage{storage: crud.New(TypeLabelValue, secrets, clock, 0)}
}

// TODO expose other methods as needed for get, create, update, etc.

// GetName returns the name of the Secret which would be used to store data for the given signature.
func (s *OIDCClientSecretStorage) GetName(oidcClientUID types.UID) string {
	// Avoid having s.storage.GetName() base64 decode something that wasn't ever encoded by encoding it here.
	b64encodedUID := base64.RawURLEncoding.EncodeToString([]byte(oidcClientUID))
	return s.storage.GetName(b64encodedUID)
}

// ReadFromSecret reads the contents of a Secret as a StoredClientSecret.
func ReadFromSecret(secret *v1.Secret) (*StoredClientSecret, error) {
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
