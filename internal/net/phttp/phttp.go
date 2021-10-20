// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"crypto/x509"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/plog"
)

func Default(rootCAs *x509.CertPool) *http.Client {
	return buildClient(ptls.Default, rootCAs)
}

func Secure(rootCAs *x509.CertPool) *http.Client {
	return buildClient(ptls.Secure, rootCAs)
}

func buildClient(tlsConfigFunc ptls.ConfigFunc, rootCAs *x509.CertPool) *http.Client {
	baseRT := defaultTransport()
	baseRT.TLSClientConfig = tlsConfigFunc(rootCAs)

	return &http.Client{
		Transport: defaultWrap(baseRT),
		Timeout:   3 * time.Hour, // make it impossible for requests to hang indefinitely
	}
}

func defaultTransport() *http.Transport {
	baseRT := http.DefaultTransport.(*http.Transport).Clone()
	net.SetTransportDefaults(baseRT)
	baseRT.MaxIdleConnsPerHost = 25 // copied from client-go
	return baseRT
}

func defaultWrap(rt http.RoundTripper) http.RoundTripper {
	rt = safeDebugWrappers(rt, transport.DebugWrappers, func() bool { return plog.Enabled(plog.LevelTrace) })
	rt = transport.NewUserAgentRoundTripper(rest.DefaultKubernetesUserAgent(), rt)
	return rt
}
