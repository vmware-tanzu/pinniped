// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package accesstoken

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
	TypeLabelValue = "access-token"

	ErrInvalidAccessTokenRequestVersion = constable.Error("access token request data has wrong version")
	ErrInvalidAccessTokenRequestData    = constable.Error("access token request data must be present")

	accessTokenStorageVersion = "1"
)

type RevocationStorage interface {
	oauth2.AccessTokenStorage
	RevokeAccessToken(ctx context.Context, requestID string) error
}

var _ RevocationStorage = &accessTokenStorage{}

type accessTokenStorage struct {
	storage crud.Storage
}

type session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface) RevocationStorage {
	return &accessTokenStorage{storage: crud.New(TypeLabelValue, secrets)}
}

func (a *accessTokenStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return a.storage.DeleteByLabel(ctx, fositestorage.StorageRequestIDLabelName, requestID)
}

func (a *accessTokenStorage) CreateAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	request, err := fositestorage.ValidateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	_, err = a.storage.Create(
		ctx,
		signature,
		&session{Request: request, Version: accessTokenStorageVersion},
		map[string]string{fositestorage.StorageRequestIDLabelName: requester.GetID()},
	)
	return err
}

func (a *accessTokenStorage) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	session, _, err := a.getSession(ctx, signature)

	if err != nil {
		return nil, err
	}

	return session.Request, err
}

func (a *accessTokenStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return a.storage.Delete(ctx, signature)
}

func (a *accessTokenStorage) getSession(ctx context.Context, signature string) (*session, string, error) {
	session := newValidEmptyAccessTokenSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get access token session for %s: %w", signature, err)
	}

	if version := session.Version; version != accessTokenStorageVersion {
		return nil, "", fmt.Errorf("%w: access token session for %s has version %s instead of %s",
			ErrInvalidAccessTokenRequestVersion, signature, version, accessTokenStorageVersion)
	}

	if session.Request.ID == "" {
		return nil, "", fmt.Errorf("malformed access token session for %s: %w", signature, ErrInvalidAccessTokenRequestData)
	}

	return session, rv, nil
}

func newValidEmptyAccessTokenSession() *session {
	return &session{
		Request: &fosite.Request{
			Client:  &fosite.DefaultOpenIDConnectClient{},
			Session: &openid.DefaultSession{},
		},
	}
}
