// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	fositepkce "github.com/ory/fosite/handler/pkce"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	"go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
)

const errKubeStorageNotImplemented = constable.Error("KubeStorage does not implement this method. It should not have been called.")

type KubeStorage struct {
	authorizationCodeStorage oauth2.AuthorizeCodeStorage
	pkceStorage              fositepkce.PKCERequestStorage
	oidcStorage              openid.OpenIDConnectRequestStorage
	accessTokenStorage       accesstoken.RevocationStorage
	refreshTokenStorage      refreshtoken.RevocationStorage
}

func NewKubeStorage(secrets corev1client.SecretInterface) *KubeStorage {
	return &KubeStorage{
		authorizationCodeStorage: authorizationcode.New(secrets),
		pkceStorage:              pkce.New(secrets),
		oidcStorage:              openidconnect.New(secrets),
		accessTokenStorage:       accesstoken.New(secrets),
		refreshTokenStorage:      refreshtoken.New(secrets),
	}
}

func (k KubeStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return k.refreshTokenStorage.RevokeRefreshToken(ctx, requestID)
}

func (k KubeStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return k.accessTokenStorage.RevokeAccessToken(ctx, requestID)
}

func (k KubeStorage) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	return k.refreshTokenStorage.CreateRefreshTokenSession(ctx, signature, request)
}

func (k KubeStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	return k.refreshTokenStorage.GetRefreshTokenSession(ctx, signature, session)
}

func (k KubeStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	return k.refreshTokenStorage.DeleteRefreshTokenSession(ctx, signature)
}

func (k KubeStorage) CreateAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) (err error) {
	return k.accessTokenStorage.CreateAccessTokenSession(ctx, signature, requester)
}

func (k KubeStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	return k.accessTokenStorage.GetAccessTokenSession(ctx, signature, session)
}

func (k KubeStorage) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	return k.accessTokenStorage.DeleteAccessTokenSession(ctx, signature)
}

func (k KubeStorage) CreateOpenIDConnectSession(ctx context.Context, authcode string, requester fosite.Requester) error {
	return k.oidcStorage.CreateOpenIDConnectSession(ctx, authcode, requester)
}

func (k KubeStorage) GetOpenIDConnectSession(ctx context.Context, authcode string, requester fosite.Requester) (fosite.Requester, error) {
	return k.oidcStorage.GetOpenIDConnectSession(ctx, authcode, requester)
}

func (k KubeStorage) DeleteOpenIDConnectSession(ctx context.Context, authcode string) error {
	return k.oidcStorage.DeleteOpenIDConnectSession(ctx, authcode)
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
