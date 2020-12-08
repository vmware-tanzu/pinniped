package oidc

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

func TokenExchangeFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &TokenExchangeHandler{}
}

type TokenExchangeHandler struct {
}

func (t *TokenExchangeHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	return nil
}

func (t *TokenExchangeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	return nil
}
