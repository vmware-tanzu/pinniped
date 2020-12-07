// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package refreshtoken

import (
	"context"
	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
)

const (
	TypeLabelValue = "refresh-token"

	ErrInvalidRefreshTokenRequestVersion = constable.Error("refresh token request data has wrong version")
	ErrInvalidRefreshTokenRequestData    = constable.Error("refresh token request data must be present")

	refreshTokenStorageVersion = "1"
)

type RevocationStorage interface {
	oauth2.RefreshTokenStorage
	RevokeRefreshToken(ctx context.Context, requestID string) error
}

var _ RevocationStorage = &refreshTokenStorage{}

type refreshTokenStorage struct {
	storage crud.Storage
}

type session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface) RevocationStorage {
	return &refreshTokenStorage{storage: crud.New(TypeLabelValue, secrets)}
}

func (a *refreshTokenStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return a.storage.DeleteByLabel(ctx, fositestorage.StorageRequestIDLabelName, requestID)
}

func (a *refreshTokenStorage) CreateRefreshTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	request, err := fositestorage.ValidateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	_, err = a.storage.Create(
		ctx,
		signature,
		&session{Request: request, Version: refreshTokenStorageVersion},
		map[string]string{fositestorage.StorageRequestIDLabelName: requester.GetID()},
	)
	return err
}

func (a *refreshTokenStorage) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	session, _, err := a.getSession(ctx, signature)

	if err != nil {
		return nil, err
	}

	return session.Request, err
}

func (a *refreshTokenStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return a.storage.Delete(ctx, signature)
}

func (a *refreshTokenStorage) getSession(ctx context.Context, signature string) (*session, string, error) {
	session := newValidEmptyRefreshTokenSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get refresh token session for %s: %w", signature, err)
	}

	if version := session.Version; version != refreshTokenStorageVersion {
		return nil, "", fmt.Errorf("%w: refresh token session for %s has version %s instead of %s",
			ErrInvalidRefreshTokenRequestVersion, signature, version, refreshTokenStorageVersion)
	}

	if session.Request.ID == "" {
		return nil, "", fmt.Errorf("malformed refresh token session for %s: %w", signature, ErrInvalidRefreshTokenRequestData)
	}

	return session, rv, nil
}

func newValidEmptyRefreshTokenSession() *session {
	return &session{
		Request: &fosite.Request{
			Client:  &fosite.DefaultOpenIDConnectClient{},
			Session: &openid.DefaultSession{},
		},
	}
}
