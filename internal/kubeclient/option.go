// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
)

type Option func(*clientConfig)

type clientConfig struct {
	config           *restclient.Config
	middlewares      []Middleware
	transportWrapper transport.WrapperFunc
}

func WithConfig(config *restclient.Config) Option {
	return func(c *clientConfig) {
		c.config = config
	}
}

func WithMiddleware(middleware Middleware) Option {
	return func(c *clientConfig) {
		if middleware == nil {
			return // support passing in a nil middleware as a no-op
		}

		c.middlewares = append(c.middlewares, middleware)
	}
}

// WithTransportWrapper will wrap the client-go http.RoundTripper chain *after* the middleware
// wrapper is applied. I.e., this wrapper has the opportunity to supply an http.RoundTripper that
// runs first in the client-go http.RoundTripper chain.
func WithTransportWrapper(wrapper transport.WrapperFunc) Option {
	return func(c *clientConfig) {
		c.transportWrapper = wrapper
	}
}
