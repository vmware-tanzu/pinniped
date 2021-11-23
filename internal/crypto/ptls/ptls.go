// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"

	"k8s.io/apiserver/pkg/admission"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/options"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
)

// TODO decide if we need to expose the four TLS levels (secure, default, default-ldap, legacy) as config.

type ConfigFunc func(*x509.CertPool) *tls.Config

func Default(rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		//
		// The Kubernetes API Server must use TLS 1.2, at a minimum,
		// to protect the confidentiality of sensitive data during electronic dissemination.
		// https://stigviewer.com/stig/kubernetes/2021-06-17/finding/V-242378
		MinVersion: tls.VersionTLS12,

		// the order does not matter in go 1.17+ https://go.dev/blog/tls-cipher-suites
		// we match crypto/tls.cipherSuitesPreferenceOrder because it makes unit tests easier to write
		// this list is ignored when TLS 1.3 is used
		//
		// as of 2021-10-19, Mozilla Guideline v5.6, Go 1.17.2, intermediate configuration, supports:
		// - Firefox 27
		// - Android 4.4.2
		// - Chrome 31
		// - Edge
		// - IE 11 on Windows 7
		// - Java 8u31
		// - OpenSSL 1.0.1
		// - Opera 20
		// - Safari 9
		// https://ssl-config.mozilla.org/#server=go&version=1.17.2&config=intermediate&guideline=5.6
		//
		// The Kubernetes API server must use approved cipher suites.
		// https://stigviewer.com/stig/kubernetes/2021-06-17/finding/V-242418
		CipherSuites: []uint16{
			// these are all AEADs with ECDHE, some use ChaCha20Poly1305 while others use AES-GCM
			// this provides forward secrecy, confidentiality and authenticity of data
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}

func Secure(rootCAs *x509.CertPool) *tls.Config {
	// as of 2021-10-19, Mozilla Guideline v5.6, Go 1.17.2, modern configuration, supports:
	// - Firefox 63
	// - Android 10.0
	// - Chrome 70
	// - Edge 75
	// - Java 11
	// - OpenSSL 1.1.1
	// - Opera 57
	// - Safari 12.1
	// https://ssl-config.mozilla.org/#server=go&version=1.17.2&config=modern&guideline=5.6
	c := Default(rootCAs)
	c.MinVersion = tls.VersionTLS13 // max out the security
	c.CipherSuites = []uint16{
		// TLS 1.3 ciphers are not configurable, but we need to explicitly set them here to make our client hello behave correctly
		// See https://github.com/golang/go/pull/49293
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	return c
}

func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	c := Default(rootCAs)
	// add less secure ciphers to support the default AWS Active Directory config
	c.CipherSuites = append(c.CipherSuites,
		// CBC with ECDHE
		// this provides forward secrecy and confidentiality of data but not authenticity
		// MAC-then-Encrypt CBC ciphers are susceptible to padding oracle attacks
		// See https://crypto.stackexchange.com/a/205 and https://crypto.stackexchange.com/a/224
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	)
	return c
}

func Legacy(rootCAs *x509.CertPool) *tls.Config {
	c := Default(rootCAs)
	// add all the ciphers (even the crappy ones) except the ones that Go considers to be outright broken like 3DES
	c.CipherSuites = suitesToIDs(tls.CipherSuites())
	return c
}

func suitesToIDs(suites []*tls.CipherSuite) []uint16 {
	out := make([]uint16, 0, len(suites))
	for _, suite := range suites {
		suite := suite
		out = append(out, suite.ID)
	}
	return out
}

func Merge(tlsConfigFunc ConfigFunc, tlsConfig *tls.Config) {
	secureTLSConfig := tlsConfigFunc(nil)

	// override the core security knobs of the TLS config
	// note that these have to be kept in sync with Default / Secure above
	tlsConfig.MinVersion = secureTLSConfig.MinVersion
	tlsConfig.CipherSuites = secureTLSConfig.CipherSuites

	// if the TLS config already states what protocols it wants to use, honor that instead of overriding
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = secureTLSConfig.NextProtos
	}
}

// RestConfigFunc allows this package to not depend on the kubeclient package.
type RestConfigFunc func(*rest.Config) (kubernetes.Interface, *rest.Config, error)

func DefaultRecommendedOptions(opts *options.RecommendedOptions, f RestConfigFunc) error {
	defaultServing(opts.SecureServing)
	return secureClient(opts, f)
}

func SecureRecommendedOptions(opts *options.RecommendedOptions, f RestConfigFunc) error {
	secureServing(opts.SecureServing)
	return secureClient(opts, f)
}

func defaultServing(opts *options.SecureServingOptionsWithLoopback) {
	c := Default(nil)
	cipherSuites := make([]string, 0, len(c.CipherSuites))
	for _, id := range c.CipherSuites {
		cipherSuites = append(cipherSuites, tls.CipherSuiteName(id))
	}
	opts.CipherSuites = cipherSuites

	opts.MinTLSVersion = "VersionTLS12"
}

func secureServing(opts *options.SecureServingOptionsWithLoopback) {
	opts.MinTLSVersion = "VersionTLS13"
	opts.CipherSuites = nil
}

func secureClient(opts *options.RecommendedOptions, f RestConfigFunc) error {
	inClusterClient, inClusterConfig, err := f(nil)
	if err != nil {
		return fmt.Errorf("failed to build in cluster client: %w", err)
	}

	if n, z := opts.Authentication.RemoteKubeConfigFile, opts.Authorization.RemoteKubeConfigFile; len(n) > 0 || len(z) > 0 {
		return fmt.Errorf("delgating auth is not using in-cluster config:\nauthentication=%s\nauthorization=%s", n, z)
	}

	// delegated authn and authz provide easy hooks for us to set the TLS config.
	// however, the underlying clients use client-go's global TLS cache with an
	// in-cluster config.  to make this safe, we simply do the mutation once.
	wrapperFunc := wrapTransportOnce(inClusterConfig.WrapTransport)
	opts.Authentication.CustomRoundTripperFn = wrapperFunc
	opts.Authorization.CustomRoundTripperFn = wrapperFunc

	opts.CoreAPI = nil // set this to nil to make sure our ExtraAdmissionInitializers is used
	baseExtraAdmissionInitializers := opts.ExtraAdmissionInitializers
	opts.ExtraAdmissionInitializers = func(c *genericapiserver.RecommendedConfig) ([]admission.PluginInitializer, error) {
		// abuse this closure to rewrite how we load admission plugins
		c.ClientConfig = inClusterConfig
		c.SharedInformerFactory = kubeinformers.NewSharedInformerFactory(inClusterClient, 0)

		// abuse this closure to rewrite our loopback config
		// this is mostly future proofing for post start hooks
		_, loopbackConfig, err := f(c.LoopbackClientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build loopback config: %w", err)
		}
		c.LoopbackClientConfig = loopbackConfig

		return baseExtraAdmissionInitializers(c)
	}

	return nil
}

func wrapTransportOnce(f transport.WrapperFunc) transport.WrapperFunc {
	var once sync.Once
	return func(rt http.RoundTripper) http.RoundTripper {
		once.Do(func() {
			_ = f(rt) // assume in-place mutation
		})
		return rt
	}
}
