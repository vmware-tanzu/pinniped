// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package fositestoragei

import (
	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
)

// This interface seems to be missing from Fosite.
// Not having this interface makes it a pain to avoid cyclical test dependencies, so we'll define it.
type AllFositeStorage interface {
	fosite.ClientManager
	fositeoauth2.CoreStorage
	fositeoauth2.TokenRevocationStorage
	openid.OpenIDConnectRequestStorage
	pkce.PKCERequestStorage
}
