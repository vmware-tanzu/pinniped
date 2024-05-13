// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"net/http"

	"github.com/go-logr/logr"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/pkg/oidcclient"
)

// OIDCClientOptions is an interface that wraps the creation of Options for the purpose of making them
// more friendly to unit tests. Because the Option type refers to a private struct type, it is hard
// to create mocks for them in tests of other packages. This provides a seam that can be mocked.
type OIDCClientOptions interface {
	WithContext(ctx context.Context) oidcclient.Option
	WithLogger(logger logr.Logger) oidcclient.Option
	WithLoginLogger(logger oidcclient.Logger) oidcclient.Option
	WithListenPort(port uint16) oidcclient.Option
	WithSkipBrowserOpen() oidcclient.Option
	WithSkipListen() oidcclient.Option
	WithSkipPrintLoginURL() oidcclient.Option
	WithSessionCache(cache oidcclient.SessionCache) oidcclient.Option
	WithClient(httpClient *http.Client) oidcclient.Option
	WithScopes(scopes []string) oidcclient.Option
	WithRequestAudience(audience string) oidcclient.Option
	WithLoginFlow(loginFlow v1alpha1.IDPFlow, flowSource string) oidcclient.Option
	WithUpstreamIdentityProvider(upstreamName, upstreamType string) oidcclient.Option
}

// clientOptions implements OIDCClientOptions for production use.
type clientOptions struct{}

var _ OIDCClientOptions = (*clientOptions)(nil)

func (o *clientOptions) WithContext(ctx context.Context) oidcclient.Option {
	return oidcclient.WithContext(ctx)
}

func (o *clientOptions) WithLogger(logger logr.Logger) oidcclient.Option {
	return oidcclient.WithLogger(logger) //nolint:staticcheck // this is a shim for the deprecated code
}

func (o *clientOptions) WithLoginLogger(logger oidcclient.Logger) oidcclient.Option {
	return oidcclient.WithLoginLogger(logger)
}

func (o *clientOptions) WithListenPort(port uint16) oidcclient.Option {
	return oidcclient.WithListenPort(port)
}

func (o *clientOptions) WithSkipBrowserOpen() oidcclient.Option {
	return oidcclient.WithSkipBrowserOpen()
}

func (o *clientOptions) WithSkipListen() oidcclient.Option {
	return oidcclient.WithSkipListen()
}

func (o *clientOptions) WithSkipPrintLoginURL() oidcclient.Option {
	return oidcclient.WithSkipPrintLoginURL()
}

func (o *clientOptions) WithSessionCache(cache oidcclient.SessionCache) oidcclient.Option {
	return oidcclient.WithSessionCache(cache)
}

func (o *clientOptions) WithClient(httpClient *http.Client) oidcclient.Option {
	return oidcclient.WithClient(httpClient)
}

func (o *clientOptions) WithScopes(scopes []string) oidcclient.Option {
	return oidcclient.WithScopes(scopes)
}

func (o *clientOptions) WithRequestAudience(audience string) oidcclient.Option {
	return oidcclient.WithRequestAudience(audience)
}

func (o *clientOptions) WithLoginFlow(loginFlow v1alpha1.IDPFlow, flowSource string) oidcclient.Option {
	return oidcclient.WithLoginFlow(loginFlow, flowSource)
}

func (o *clientOptions) WithUpstreamIdentityProvider(upstreamName, upstreamType string) oidcclient.Option {
	return oidcclient.WithUpstreamIdentityProvider(upstreamName, upstreamType)
}
