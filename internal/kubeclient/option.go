// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import restclient "k8s.io/client-go/rest"

type Option func(*clientConfig)

type clientConfig struct {
	config      *restclient.Config
	middlewares []Middleware
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
