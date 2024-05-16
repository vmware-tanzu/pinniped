// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
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
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
)

// TODO decide if we need to expose the four TLS levels (secure, default, default-ldap, legacy) as config.

// defaultServingOptionsMinTLSVersion is the minimum tls version in the format
// expected by SecureServingOptions.MinTLSVersion from
// k8s.io/apiserver/pkg/server/options.
const defaultServingOptionsMinTLSVersion = "VersionTLS12"

type ConfigFunc func(*x509.CertPool) *tls.Config

func Legacy(rootCAs *x509.CertPool) *tls.Config {
	c := Default(rootCAs)
	// add all the ciphers (even the crappy ones) except the ones that Go considers to be outright broken like 3DES
	c.CipherSuites = suitesToIDs(tls.CipherSuites())
	return c
}

func suitesToIDs(suites []*tls.CipherSuite) []uint16 {
	out := make([]uint16, 0, len(suites))
	for _, suite := range suites {
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

// PrepareServerConfigFunc is a function that can prepare a RecommendedConfig before the use of RecommendedOptions.ApplyTo().
type PrepareServerConfigFunc func(c *genericapiserver.RecommendedConfig)

// DefaultRecommendedOptions configures the RecommendedOptions for a server to use the appropriate cipher suites,
// min TLS version, and client configuration options for servers that need to accept incoming connections from
// arbitrary clients (like the impersonation proxy).
// It returns a PrepareServerConfigFunc which must be used on a RecommendedConfig before passing it to RecommendedOptions.ApplyTo().
func DefaultRecommendedOptions(opts *options.RecommendedOptions, f RestConfigFunc) (PrepareServerConfigFunc, error) {
	defaultServing(opts.SecureServing)
	return secureClient(opts, f)
}

// SecureRecommendedOptions configures the RecommendedOptions for a server to use the appropriate cipher suites,
// min TLS version, and client configuration options for servers that only need to accept incoming connections from
// certain well known clients which we expect will always use modern TLS settings (like the Kube API server).
// It returns a PrepareServerConfigFunc which must be used on a RecommendedConfig before passing it to RecommendedOptions.ApplyTo().
func SecureRecommendedOptions(opts *options.RecommendedOptions, f RestConfigFunc) (PrepareServerConfigFunc, error) {
	SecureServing(opts.SecureServing)
	return secureClient(opts, f)
}

func defaultServing(opts *options.SecureServingOptionsWithLoopback) {
	c := Default(nil)
	cipherSuites := make([]string, 0, len(c.CipherSuites))
	for _, id := range c.CipherSuites {
		cipherSuites = append(cipherSuites, tls.CipherSuiteName(id))
	}
	opts.CipherSuites = cipherSuites

	opts.MinTLSVersion = defaultServingOptionsMinTLSVersion
}

func secureClient(opts *options.RecommendedOptions, f RestConfigFunc) (PrepareServerConfigFunc, error) {
	inClusterClient, inClusterConfig, err := f(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build in cluster client: %w", err)
	}

	if n, z := opts.Authentication.RemoteKubeConfigFile, opts.Authorization.RemoteKubeConfigFile; len(n) > 0 || len(z) > 0 {
		return nil, fmt.Errorf("delgating auth is not using in-cluster config:\nauthentication=%s\nauthorization=%s", n, z)
	}

	// delegated authn and authz provide easy hooks for us to set the TLS config.
	// however, the underlying clients use client-go's global TLS cache with an
	// in-cluster config.  to make this safe, we simply do the mutation once.
	wrapperFunc := wrapTransportOnce(inClusterConfig.WrapTransport)
	opts.Authentication.CustomRoundTripperFn = wrapperFunc
	opts.Authorization.CustomRoundTripperFn = wrapperFunc

	// Set this to nil to because it would normally set up c.ClientConfig and c.SharedInformerFactory, but we want to
	// do that ourselves instead by calling the func returned below before we call RecommendedOptions.ApplyTo().
	opts.CoreAPI = nil

	baseExtraAdmissionInitializers := opts.ExtraAdmissionInitializers
	opts.ExtraAdmissionInitializers = func(c *genericapiserver.RecommendedConfig) ([]admission.PluginInitializer, error) {
		// Abuse this closure to rewrite our loopback config. This is mostly future proofing for post start hooks.
		// Note that c.LoopbackClientConfig has already been set up inside RecommendedOptions.ApplyTo() before this
		// ExtraAdmissionInitializers function is invoked, so it is okay to use it here.
		_, loopbackConfig, err := f(c.LoopbackClientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build loopback config: %w", err)
		}
		c.LoopbackClientConfig = loopbackConfig
		return baseExtraAdmissionInitializers(c)
	}

	// This returned function is intended to be called before RecommendedOptions.ApplyTo(). Is is intended
	// that the above setting of opts.CoreAPI to nil will make the below function the only thing that sets
	// the c.ClientConfig and c.SharedInformerFactory, although this is highly dependent on the implementation
	// details ofRecommendedOptions.ApplyTo() and all its helpers that it invokes.
	return func(c *genericapiserver.RecommendedConfig) {
		c.ClientConfig = inClusterConfig
		c.SharedInformerFactory = k8sinformers.NewSharedInformerFactory(inClusterClient, 0)
	}, nil
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
