// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"

	"github.com/ory/fosite/handler/openid"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

func TokenExchangeFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &TokenExchangeHandler{
		strategy.(openid.OpenIDConnectTokenStrategy),
		strategy.(oauth2.AccessTokenStrategy),
		storage.(oauth2.AccessTokenStorage),
	}
}

type TokenExchangeHandler struct {
	idTokenStrategy     openid.OpenIDConnectTokenStrategy
	accessTokenStrategy oauth2.AccessTokenStrategy
	accessTokenStorage  oauth2.AccessTokenStorage
}

func (t *TokenExchangeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !(requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}
	return nil
}

func (t *TokenExchangeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !(requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}
	params := requester.GetRequestForm()
	accessToken := params.Get("subject_token")
	if err := t.accessTokenStrategy.ValidateAccessToken(ctx, requester, accessToken); err != nil {
		return errors.WithStack(err)
	}
	signature := t.accessTokenStrategy.AccessTokenSignature(accessToken)
	accessTokenSession, err := t.accessTokenStorage.GetAccessTokenSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errors.WithStack(err)
	}
	if !accessTokenSession.GetGrantedScopes().Has("pinniped.sts.unrestricted") {
		return errors.WithStack(fosite.ErrScopeNotGranted)
	}
	// TODO check the other requester fields
	scopedDownRequester := fosite.NewAccessRequest(accessTokenSession.GetSession())
	scopedDownRequester.GrantedAudience = []string{params.Get("audience")}
	newToken, err := t.idTokenStrategy.GenerateIDToken(ctx, scopedDownRequester)
	if err != nil {
		return errors.WithStack(err)
	}
	responder.SetAccessToken(newToken)
	responder.SetTokenType("N_A")
	responder.SetExtra("issued_token_type", "urn:ietf:params:oauth:token-type:jwt")
	return nil
}
