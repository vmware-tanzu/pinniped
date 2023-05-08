// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/pkce"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/clientregistry"
	"go.pinniped.dev/internal/psession"
)

const (
	TypeLabelValue = "pkce"

	ErrInvalidPKCERequestVersion = constable.Error("pkce request data has wrong version")
	ErrInvalidPKCERequestData    = constable.Error("pkce request data must be present")

	// Version 1 was the initial release of storage.
	// Version 2 is when we switched to storing psession.PinnipedSession inside the fosite request.
	// Version 3 is when we added the Username field to the psession.CustomSessionData.
	// Version 4 is when fosite added json tags to their openid.DefaultSession struct.
	// Version 5 is when we added the UpstreamUsername and UpstreamGroups fields to psession.CustomSessionData.
	pkceStorageVersion = "5"
)

var _ pkce.PKCERequestStorage = &pkceStorage{}

type pkceStorage struct {
	storage crud.Storage
}

type session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime time.Duration) pkce.PKCERequestStorage {
	return &pkceStorage{storage: crud.New(TypeLabelValue, secrets, clock, sessionStorageLifetime)}
}

func (a *pkceStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	request, err := fositestorage.ValidateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	_, err = a.storage.Create(ctx, signature, &session{Request: request, Version: pkceStorageVersion}, nil, nil)
	return err
}

func (a *pkceStorage) GetPKCERequestSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	session, _, err := a.getSession(ctx, signature)

	if err != nil {
		return nil, err
	}

	return session.Request, err
}

func (a *pkceStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return a.storage.Delete(ctx, signature)
}

func (a *pkceStorage) getSession(ctx context.Context, signature string) (*session, string, error) {
	session := newValidEmptyPKCESession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithWrap(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get pkce session for %s: %w", signature, err)
	}

	if version := session.Version; version != pkceStorageVersion {
		return nil, "", fmt.Errorf("%w: pkce session for %s has version %s instead of %s",
			ErrInvalidPKCERequestVersion, signature, version, pkceStorageVersion)
	}

	if session.Request.ID == "" {
		return nil, "", fmt.Errorf("malformed pkce session for %s: %w", signature, ErrInvalidPKCERequestData)
	}

	return session, rv, nil
}

func newValidEmptyPKCESession() *session {
	return &session{
		Request: &fosite.Request{
			Client:  &clientregistry.Client{},
			Session: &psession.PinnipedSession{},
		},
	}
}
