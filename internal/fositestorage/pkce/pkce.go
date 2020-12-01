// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
)

const (
	ErrInvalidPKCERequestType = constable.Error("requester must be of type fosite.Request")

	pkceStorageVersion = "1"
)

var _ pkce.PKCERequestStorage = &pkceStorage{}

type pkceStorage struct {
	storage crud.Storage
}

type session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface) pkce.PKCERequestStorage {
	return &pkceStorage{storage: crud.New("pkce", secrets)}
}

// TODO test what happens when we pass nil as the requester.
func (a *pkceStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	request, err := validateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	_, err = a.storage.Create(ctx, signature, &session{Request: request, Version: pkceStorageVersion})
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

	// TODO we do want this
	// if errors.IsNotFound(err) {
	// 	return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
	// }

	if err != nil {
		return nil, "", fmt.Errorf("failed to get authorization code session for %s: %w", signature, err)
	}

	// TODO we probably want this
	// if version := session.Version; version != pkceStorageVersion {
	// 	return nil, "", fmt.Errorf("%w: authorization code session for %s has version %s instead of %s",
	// 		ErrInvalidAuthorizeRequestVersion, signature, version, pkceStorageVersion)
	// }

	// TODO maybe we want this. it would only apply when a human has edited the secret.
	// if session.Request == nil {
	// 	return nil, "", fmt.Errorf("malformed authorization code session for %s: %w", signature, ErrInvalidAuthorizeRequestData)
	// }

	return session, rv, nil
}

func newValidEmptyPKCESession() *session {
	return &session{
		Request: &fosite.Request{
			Client:  &fosite.DefaultOpenIDConnectClient{},
			Session: &openid.DefaultSession{},
		},
	}
}

func validateAndExtractAuthorizeRequest(requester fosite.Requester) (*fosite.Request, error) {
	request, ok1 := requester.(*fosite.Request)
	if !ok1 {
		return nil, ErrInvalidPKCERequestType
	}
	_, ok2 := request.Client.(*fosite.DefaultOpenIDConnectClient)
	_, ok3 := request.Session.(*openid.DefaultSession)

	valid := ok2 && ok3
	if !valid {
		return nil, ErrInvalidPKCERequestType
	}

	return request, nil
}
