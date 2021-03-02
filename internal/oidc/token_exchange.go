// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/pkg/errors"
)

const (
	tokenTypeAccessToken       = "urn:ietf:params:oauth:token-type:access_token" //nolint: gosec
	tokenTypeJWT               = "urn:ietf:params:oauth:token-type:jwt"          //nolint: gosec
	pinnipedTokenExchangeScope = "pinniped:request-audience"                     //nolint: gosec
)

type stsParams struct {
	subjectAccessToken string
	requestedAudience  string
}

func TokenExchangeFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &TokenExchangeHandler{
		idTokenStrategy:     strategy.(openid.OpenIDConnectTokenStrategy),
		accessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
		accessTokenStorage:  storage.(oauth2.AccessTokenStorage),
	}
}

type TokenExchangeHandler struct {
	idTokenStrategy     openid.OpenIDConnectTokenStrategy
	accessTokenStrategy oauth2.AccessTokenStrategy
	accessTokenStorage  oauth2.AccessTokenStorage
}

var _ fosite.TokenEndpointHandler = (*TokenExchangeHandler)(nil)

func (t *TokenExchangeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !t.CanHandleTokenEndpointRequest(requester) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}
	return nil
}

func (t *TokenExchangeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	// Skip this request if it's for a different grant type.
	if err := t.HandleTokenEndpointRequest(ctx, requester); err != nil {
		return errors.WithStack(err)
	}

	// Validate the basic RFC8693 parameters we support.
	params, err := t.validateParams(requester.GetRequestForm())
	if err != nil {
		return errors.WithStack(err)
	}

	// Validate the incoming access token and lookup the information about the original authorize request.
	originalRequester, err := t.validateAccessToken(ctx, requester, params.subjectAccessToken)
	if err != nil {
		return errors.WithStack(err)
	}

	// Require that the incoming access token has the pinniped:request-audience and OpenID scopes.
	if !originalRequester.GetGrantedScopes().Has(pinnipedTokenExchangeScope) {
		return errors.WithStack(fosite.ErrAccessDenied.WithHintf("missing the %q scope", pinnipedTokenExchangeScope))
	}
	if !originalRequester.GetGrantedScopes().Has(oidc.ScopeOpenID) {
		return errors.WithStack(fosite.ErrAccessDenied.WithHintf("missing the %q scope", oidc.ScopeOpenID))
	}

	// Use the original authorize request information, along with the requested audience, to mint a new JWT.
	responseToken, err := t.mintJWT(ctx, originalRequester, params.requestedAudience)
	if err != nil {
		return errors.WithStack(err)
	}

	// Format the response parameters according to RFC8693.
	responder.SetAccessToken(responseToken)
	responder.SetTokenType("N_A")
	responder.SetExtra("issued_token_type", tokenTypeJWT)
	return nil
}

func (t *TokenExchangeHandler) mintJWT(ctx context.Context, requester fosite.Requester, audience string) (string, error) {
	downscoped := fosite.NewAccessRequest(requester.GetSession())
	downscoped.Client.(*fosite.DefaultClient).ID = audience
	return t.idTokenStrategy.GenerateIDToken(ctx, downscoped)
}

func (t *TokenExchangeHandler) validateParams(params url.Values) (*stsParams, error) {
	var result stsParams

	// Validate some required parameters.
	result.requestedAudience = params.Get("audience")
	if result.requestedAudience == "" {
		return nil, fosite.ErrInvalidRequest.WithHint("missing audience parameter")
	}
	result.subjectAccessToken = params.Get("subject_token")
	if result.subjectAccessToken == "" {
		return nil, fosite.ErrInvalidRequest.WithHint("missing subject_token parameter")
	}

	// Validate some parameters with hardcoded values we support.
	if params.Get("subject_token_type") != tokenTypeAccessToken {
		return nil, fosite.ErrInvalidRequest.WithHintf("unsupported subject_token_type parameter value, must be %q", tokenTypeAccessToken)
	}
	if params.Get("requested_token_type") != tokenTypeJWT {
		return nil, fosite.ErrInvalidRequest.WithHintf("unsupported requested_token_type parameter value, must be %q", tokenTypeJWT)
	}

	// Validate that none of these unsupported parameters were sent. These are optional and we do not currently support them.
	for _, param := range []string{
		"resource",
		"scope",
		"actor_token",
		"actor_token_type",
	} {
		if params.Get(param) != "" {
			return nil, fosite.ErrInvalidRequest.WithHintf("unsupported parameter %s", param)
		}
	}

	return &result, nil
}

func (t *TokenExchangeHandler) validateAccessToken(ctx context.Context, requester fosite.AccessRequester, accessToken string) (fosite.Requester, error) {
	if err := t.accessTokenStrategy.ValidateAccessToken(ctx, requester, accessToken); err != nil {
		return nil, errors.WithStack(err)
	}
	signature := t.accessTokenStrategy.AccessTokenSignature(accessToken)
	originalRequester, err := t.accessTokenStorage.GetAccessTokenSession(ctx, signature, requester.GetSession())
	if err != nil {
		return nil, fosite.ErrRequestUnauthorized.WithWrap(err).WithHint("invalid subject_token")
	}
	return originalRequester, nil
}

func (t *TokenExchangeHandler) CanSkipClientAuth(_ fosite.AccessRequester) bool {
	return false
}

func (t *TokenExchangeHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}
