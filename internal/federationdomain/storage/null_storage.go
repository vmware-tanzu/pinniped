// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"

	"github.com/ory/fosite"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
)

const errNullStorageNotImplemented = constable.Error("NullStorage does not implement this method. It should not have been called.")

type NullStorage struct {
	// The authorization endpoint uses NullStorage to avoid saving any data, but it still needs to perform client lookups.
	*clientregistry.ClientManager
}

var _ fositestoragei.AllFositeStorage = &NullStorage{}

func NewNullStorage(
	secrets corev1client.SecretInterface,
	oidcClientsClient v1alpha1.OIDCClientInterface,
	minBcryptCost int,
) *NullStorage {
	return &NullStorage{
		ClientManager: clientregistry.NewClientManager(oidcClientsClient, oidcclientsecretstorage.New(secrets), minBcryptCost),
	}
}

func (NullStorage) RevokeRefreshToken(_ context.Context, _ string) error {
	return errNullStorageNotImplemented
}

func (NullStorage) RotateRefreshToken(_ context.Context, _ string, _ string) error {
	return errNullStorageNotImplemented
}

func (NullStorage) RevokeAccessToken(_ context.Context, _ string) error {
	return errNullStorageNotImplemented
}

func (NullStorage) CreateRefreshTokenSession(_ context.Context, _ string, _ string, _ fosite.Requester) (err error) {
	return nil
}

func (NullStorage) GetRefreshTokenSession(_ context.Context, _ string, _ fosite.Session) (request fosite.Requester, err error) {
	return nil, errNullStorageNotImplemented
}

func (NullStorage) DeleteRefreshTokenSession(_ context.Context, _ string) (err error) {
	return errNullStorageNotImplemented
}

func (NullStorage) CreateAccessTokenSession(_ context.Context, _ string, _ fosite.Requester) (err error) {
	return nil
}

func (NullStorage) GetAccessTokenSession(_ context.Context, _ string, _ fosite.Session) (request fosite.Requester, err error) {
	return nil, errNullStorageNotImplemented
}

func (NullStorage) DeleteAccessTokenSession(_ context.Context, _ string) (err error) {
	return errNullStorageNotImplemented
}

func (NullStorage) CreateOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) error {
	return nil
}

func (NullStorage) GetOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) (fosite.Requester, error) {
	return nil, errNullStorageNotImplemented
}

func (NullStorage) DeleteOpenIDConnectSession(_ context.Context, _ string) error {
	return errNullStorageNotImplemented
}

func (NullStorage) GetPKCERequestSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	return nil, errNullStorageNotImplemented
}

func (NullStorage) CreatePKCERequestSession(_ context.Context, _ string, _ fosite.Requester) error {
	return nil
}

func (NullStorage) DeletePKCERequestSession(_ context.Context, _ string) error {
	return errNullStorageNotImplemented
}

func (NullStorage) CreateAuthorizeCodeSession(_ context.Context, _ string, _ fosite.Requester) (err error) {
	return nil
}

func (NullStorage) GetAuthorizeCodeSession(_ context.Context, _ string, _ fosite.Session) (request fosite.Requester, err error) {
	return nil, errNullStorageNotImplemented
}

func (NullStorage) InvalidateAuthorizeCodeSession(_ context.Context, _ string) (err error) {
	return errNullStorageNotImplemented
}
