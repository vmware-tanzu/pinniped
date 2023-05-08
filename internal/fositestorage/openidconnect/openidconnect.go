// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package openidconnect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/clientregistry"
	"go.pinniped.dev/internal/psession"
)

const (
	TypeLabelValue = "oidc"

	ErrInvalidOIDCRequestVersion  = constable.Error("oidc request data has wrong version")
	ErrInvalidOIDCRequestData     = constable.Error("oidc request data must be present")
	ErrMalformedAuthorizationCode = constable.Error("malformed authorization code")

	// Version 1 was the initial release of storage.
	// Version 2 is when we switched to storing psession.PinnipedSession inside the fosite request.
	// Version 3 is when we added the Username field to the psession.CustomSessionData.
	// Version 4 is when fosite added json tags to their openid.DefaultSession struct.
	// Version 5 is when we added the UpstreamUsername and UpstreamGroups fields to psession.CustomSessionData.
	oidcStorageVersion = "5"
)

var _ openid.OpenIDConnectRequestStorage = &openIDConnectRequestStorage{}

type openIDConnectRequestStorage struct {
	storage crud.Storage
}

type session struct {
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime time.Duration) openid.OpenIDConnectRequestStorage {
	return &openIDConnectRequestStorage{storage: crud.New(TypeLabelValue, secrets, clock, sessionStorageLifetime)}
}

func (a *openIDConnectRequestStorage) CreateOpenIDConnectSession(ctx context.Context, authcode string, requester fosite.Requester) error {
	signature, err := getSignature(authcode)
	if err != nil {
		return err
	}

	request, err := fositestorage.ValidateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	_, err = a.storage.Create(ctx, signature, &session{Request: request, Version: oidcStorageVersion}, nil, nil)
	return err
}

func (a *openIDConnectRequestStorage) GetOpenIDConnectSession(ctx context.Context, authcode string, _ fosite.Requester) (fosite.Requester, error) {
	signature, err := getSignature(authcode)
	if err != nil {
		return nil, err
	}

	session, _, err := a.getSession(ctx, signature)

	if err != nil {
		return nil, err
	}

	return session.Request, err
}

func (a *openIDConnectRequestStorage) DeleteOpenIDConnectSession(ctx context.Context, authcode string) error {
	signature, err := getSignature(authcode)
	if err != nil {
		return err
	}

	return a.storage.Delete(ctx, signature)
}

func (a *openIDConnectRequestStorage) getSession(ctx context.Context, signature string) (*session, string, error) {
	session := newValidEmptyOIDCSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithWrap(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get oidc session for %s: %w", signature, err)
	}

	if version := session.Version; version != oidcStorageVersion {
		return nil, "", fmt.Errorf("%w: oidc session for %s has version %s instead of %s",
			ErrInvalidOIDCRequestVersion, signature, version, oidcStorageVersion)
	}

	if session.Request.ID == "" {
		return nil, "", fmt.Errorf("malformed oidc session for %s: %w", signature, ErrInvalidOIDCRequestData)
	}

	return session, rv, nil
}

func newValidEmptyOIDCSession() *session {
	return &session{
		Request: &fosite.Request{
			Client:  &clientregistry.Client{},
			Session: &psession.PinnipedSession{},
		},
	}
}

func getSignature(authorizationCode string) (string, error) {
	split := strings.Split(authorizationCode, ".")

	if len(split) != 2 {
		return "", ErrMalformedAuthorizationCode
	}

	return split[1], nil
}
