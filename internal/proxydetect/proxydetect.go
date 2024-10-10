// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package proxydetect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type ProxyDetect interface {
	// UsingProxyForHost returns true if HTTPS requests made to the specified host would be sent through a web proxy.
	// It returns false if requests would not be sent through a proxy. It returns an error if it cannot be determined.
	UsingProxyForHost(host string) (bool, error)
}

type detector struct {
	// The real http.ProxyFromEnvironment func only reads the env vars once, and then never reads them again
	// for the rest of the process's lifetime. This makes it hard to write unit tests that use the real func,
	// because you cannot vary the env variables' values between tests, so we'll use a fake in unit tests.
	proxyFromEnvironmentFunc func(req *http.Request) (*url.URL, error)
}

var _ ProxyDetect = (*detector)(nil)

func New() ProxyDetect {
	return &detector{proxyFromEnvironmentFunc: http.ProxyFromEnvironment}
}

func (d *detector) UsingProxyForHost(host string) (bool, error) {
	const msgFmt = "could not determine if requests will be proxied for host %q: %v"

	// Make a request object that represents any HTTPS request to the specified server.
	// The other parameter values don't matter, as long as they are valid, because we won't actually make this request.
	r, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		fmt.Sprintf("https://%s", host),
		nil,
	)
	if err != nil {
		// This will return an error if the host string has an invalid format.
		return false, fmt.Errorf(msgFmt, host, err)
	}

	// Ask if the request would use a proxy or not. This does not actually make the request.
	proxyURL, err := d.proxyFromEnvironmentFunc(r)
	if err != nil {
		// This could return an error if the HTTPS_PROXY env variable's value had an invalid format, for example.
		return false, fmt.Errorf(msgFmt, host, err)
	}

	return proxyURL != nil, nil
}
