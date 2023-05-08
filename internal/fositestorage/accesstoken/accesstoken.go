// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/clientregistry"
	"go.pinniped.dev/internal/psession"
)

const (
	TypeLabelValue = "access-token"

	ErrInvalidAccessTokenRequestVersion = constable.Error("access token request data has wrong version")
	ErrInvalidAccessTokenRequestData    = constable.Error("access token request data must be present")

	// Version 1 was the initial release of storage.
	// Version 2 is when we switched to storing psession.PinnipedSession inside the fosite request.
	// Version 3 is when we added the Username field to the psession.CustomSessionData.
	// Version 4 is when fosite added json tags to their openid.DefaultSession struct.
	// Version 5 is when we added the UpstreamUsername and UpstreamGroups fields to psession.CustomSessionData.
	accessTokenStorageVersion = "5"
)

type RevocationStorage interface {
	oauth2.AccessTokenStorage
	RevokeAccessToken(ctx context.Context, requestID string) error
}

var _ RevocationStorage = &accessTokenStorage{}

type accessTokenStorage struct {
	storage crud.Storage
}

type Session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime time.Duration) RevocationStorage {
	return &accessTokenStorage{storage: crud.New(TypeLabelValue, secrets, clock, sessionStorageLifetime)}
}

// ReadFromSecret reads the contents of a Secret as a Session.
func ReadFromSecret(secret *v1.Secret) (*Session, error) {
	session := newValidEmptyAccessTokenSession()
	err := crud.FromSecret(TypeLabelValue, secret, session)
	if err != nil {
		return nil, err
	}
	if session.Version != accessTokenStorageVersion {
		return nil, fmt.Errorf("%w: access token session has version %s instead of %s",
			ErrInvalidAccessTokenRequestVersion, session.Version, accessTokenStorageVersion)
	}
	if session.Request.ID == "" {
		return nil, fmt.Errorf("malformed access token session: %w", ErrInvalidAccessTokenRequestData)
	}
	return session, nil
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
		&Session{Request: request, Version: accessTokenStorageVersion},
		map[string]string{fositestorage.StorageRequestIDLabelName: requester.GetID()},
		nil,
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

func (a *accessTokenStorage) getSession(ctx context.Context, signature string) (*Session, string, error) {
	session := newValidEmptyAccessTokenSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithWrap(err).WithDebug(err.Error())
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

func newValidEmptyAccessTokenSession() *Session {
	return &Session{
		Request: &fosite.Request{
			Client:  &clientregistry.Client{},
			Session: &psession.PinnipedSession{},
		},
	}
}
