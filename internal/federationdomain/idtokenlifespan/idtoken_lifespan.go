// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package idtokenlifespan

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
)

// contextKey type is unexported to prevent collisions.
type contextKey int

const idTokenLifetimeOverrideKey contextKey = iota

// OpenIDConnectExplicitFactory is similar to the function of the same name in the fosite compose package,
// except it allows wrapping the IDTokenLifespanProvider.
func OpenIDConnectExplicitFactory(config fosite.Configurator, storage any, strategy any) any {
	openIDConnectExplicitHandler := compose.OpenIDConnectExplicitFactory(config, storage, strategy).(*openid.OpenIDConnectExplicitHandler)
	// Overwrite the config with a wrapper around the fosite.IDTokenLifespanProvider.
	openIDConnectExplicitHandler.Config = &contextAwareIDTokenLifespanProvider{DelegateConfig: config}
	return openIDConnectExplicitHandler
}

// OpenIDConnectRefreshFactory is similar to the function of the same name in the fosite compose package,
// except it allows wrapping the IDTokenLifespanProvider.
func OpenIDConnectRefreshFactory(config fosite.Configurator, _ any, strategy any) any {
	openIDConnectRefreshHandler := compose.OpenIDConnectRefreshFactory(config, nil, strategy).(*openid.OpenIDConnectRefreshHandler)
	// Overwrite the config with a wrapper around the fosite.IDTokenLifespanProvider.
	openIDConnectRefreshHandler.Config = &contextAwareIDTokenLifespanProvider{DelegateConfig: config}
	return openIDConnectRefreshHandler
}

var _ fosite.IDTokenLifespanProvider = (*contextAwareIDTokenLifespanProvider)(nil)

type contextAwareIDTokenLifespanProvider struct {
	DelegateConfig fosite.IDTokenLifespanProvider
}

func (c *contextAwareIDTokenLifespanProvider) GetIDTokenLifespan(ctx context.Context) time.Duration {
	idTokenLifespanOverride, ok := ctx.Value(idTokenLifetimeOverrideKey).(time.Duration)
	if ok {
		return idTokenLifespanOverride
	}
	// When there is no override on the context, just return the default by calling the delegate.
	return c.DelegateConfig.GetIDTokenLifespan(ctx)
}

func OverrideIDTokenLifespanInContext(ctx context.Context, newLifespan time.Duration) context.Context {
	return context.WithValue(ctx, idTokenLifetimeOverrideKey, newLifespan)
}
