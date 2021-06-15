// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package fositestorage

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/oidc/staticclient"
)

const (
	ErrInvalidRequestType     = constable.Error("requester must be of type fosite.Request")
	ErrInvalidClientType      = constable.Error("requester's client must be of type staticclient.PinnipedCLI")
	ErrInvalidSessionType     = constable.Error("requester's session must be of type openid.DefaultSession")
	StorageRequestIDLabelName = "storage.pinniped.dev/request-id" //nolint:gosec // this is not a credential
)

func ValidateAndExtractAuthorizeRequest(requester fosite.Requester) (*fosite.Request, error) {
	request, ok1 := requester.(*fosite.Request)
	if !ok1 {
		return nil, ErrInvalidRequestType
	}
	_, ok2 := request.Client.(*staticclient.PinnipedCLI)
	if !ok2 {
		return nil, ErrInvalidClientType
	}
	_, ok3 := request.Session.(*openid.DefaultSession)
	if !ok3 {
		return nil, ErrInvalidSessionType
	}

	return request, nil
}
