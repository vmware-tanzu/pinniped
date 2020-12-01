// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"time"

	fositepkce "github.com/ory/fosite/handler/pkce"

	"go.pinniped.dev/internal/fositestorage/pkce"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
)

const errKubeStorageNotImplemented = constable.Error("KubeStorage does not implement this method. It should not have been called.")

type KubeStorage struct {
	authorizationCodeStorage oauth2.AuthorizeCodeStorage
	pkceStorage              fositepkce.PKCERequestStorage
}

func NewKubeStorage(secrets corev1client.SecretInterface) *KubeStorage {
	return &KubeStorage{
		authorizationCodeStorage: authorizationcode.New(secrets),
		pkceStorage:              pkce.New(secrets),
	}
}

func (KubeStorage) RevokeRefreshToken(_ context.Context, _ string) error {
	return errKubeStorageNotImplemented
}

func (KubeStorage) RevokeAccessToken(_ context.Context, _ string) error {
	return errKubeStorageNotImplemented
}

func (KubeStorage) CreateRefreshTokenSession(_ context.Context, _ string, _ fosite.Requester) (err error) {
	return nil
}

func (KubeStorage) GetRefreshTokenSession(_ context.Context, _ string, _ fosite.Session) (request fosite.Requester, err error) {
	return nil, errKubeStorageNotImplemented
}

func (KubeStorage) DeleteRefreshTokenSession(_ context.Context, _ string) (err error) {
	return errKubeStorageNotImplemented
}

func (KubeStorage) CreateAccessTokenSession(_ context.Context, _ string, _ fosite.Requester) (err error) {
	return nil
}

func (KubeStorage) GetAccessTokenSession(_ context.Context, _ string, _ fosite.Session) (request fosite.Requester, err error) {
	return nil, errKubeStorageNotImplemented
}

func (KubeStorage) DeleteAccessTokenSession(_ context.Context, _ string) (err error) {
	return errKubeStorageNotImplemented
}

func (KubeStorage) CreateOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) error {
	return nil
}

func (KubeStorage) GetOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) (fosite.Requester, error) {
	return nil, errKubeStorageNotImplemented
}

func (KubeStorage) DeleteOpenIDConnectSession(_ context.Context, _ string) error {
	return errKubeStorageNotImplemented
}

func (k KubeStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return k.pkceStorage.GetPKCERequestSession(ctx, signature, session)
}

func (k KubeStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return k.pkceStorage.CreatePKCERequestSession(ctx, signature, requester)
}

func (k KubeStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return k.pkceStorage.DeletePKCERequestSession(ctx, signature)
}

func (k KubeStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, r fosite.Requester) (err error) {
	return k.authorizationCodeStorage.CreateAuthorizeCodeSession(ctx, signature, r)
}

func (k KubeStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, s fosite.Session) (request fosite.Requester, err error) {
	return k.authorizationCodeStorage.GetAuthorizeCodeSession(ctx, signature, s)
}

func (k KubeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) (err error) {
	return k.authorizationCodeStorage.InvalidateAuthorizeCodeSession(ctx, signature)
}

func (KubeStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	client := PinnipedCLIOIDCClient()
	if client.ID == id {
		return client, nil
	}
	return nil, fosite.ErrNotFound
}

func (KubeStorage) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return errKubeStorageNotImplemented
}

func (KubeStorage) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return errKubeStorageNotImplemented
}
