// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/kubernetes"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	aggregatorclientscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"

	pinnipedconciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	pinnipedconciergeclientsetscheme "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/scheme"
	pinnipedsupervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	pinnipedsupervisorclientsetscheme "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/scheme"
	"go.pinniped.dev/internal/crypto/ptls"
)

type Client struct {
	Kubernetes         kubernetes.Interface
	Aggregation        aggregatorclient.Interface
	PinnipedConcierge  pinnipedconciergeclientset.Interface
	PinnipedSupervisor pinnipedsupervisorclientset.Interface

	JSONConfig, ProtoConfig *restclient.Config
}

func New(opts ...Option) (*Client, error) {
	c := &clientConfig{}

	for _, opt := range opts {
		opt(c)
	}

	// default to assuming we are running in a pod with the service account token mounted
	if c.config == nil {
		inClusterConfig, err := restclient.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
		}
		WithConfig(inClusterConfig)(c) // make sure all writes to clientConfig flow through one code path
	}

	secureKubeConfig, err := createSecureKubeConfig(c.config)
	if err != nil {
		return nil, fmt.Errorf("could not create secure client config: %w", err)
	}

	// explicitly use json when talking to CRD APIs
	jsonKubeConfig := createJSONKubeConfig(secureKubeConfig)

	// explicitly use protobuf when talking to built-in kube APIs
	protoKubeConfig := createProtoKubeConfig(secureKubeConfig)

	// Connect to the core Kubernetes API.
	k8sClient, err := kubernetes.NewForConfig(configWithWrapper(protoKubeConfig, kubescheme.Scheme, kubescheme.Codecs, c.middlewares, c.transportWrapper))
	if err != nil {
		return nil, fmt.Errorf("could not initialize Kubernetes client: %w", err)
	}

	// Connect to the Kubernetes aggregation API.
	aggregatorClient, err := aggregatorclient.NewForConfig(configWithWrapper(protoKubeConfig, aggregatorclientscheme.Scheme, aggregatorclientscheme.Codecs, c.middlewares, c.transportWrapper))
	if err != nil {
		return nil, fmt.Errorf("could not initialize aggregation client: %w", err)
	}

	// Connect to the pinniped concierge API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedConciergeClient, err := pinnipedconciergeclientset.NewForConfig(configWithWrapper(jsonKubeConfig, pinnipedconciergeclientsetscheme.Scheme, pinnipedconciergeclientsetscheme.Codecs, c.middlewares, c.transportWrapper))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	// Connect to the pinniped supervisor API.
	// We cannot use protobuf encoding here because we are using CRDs
	// (for which protobuf encoding is not yet supported).
	pinnipedSupervisorClient, err := pinnipedsupervisorclientset.NewForConfig(configWithWrapper(jsonKubeConfig, pinnipedsupervisorclientsetscheme.Scheme, pinnipedsupervisorclientsetscheme.Codecs, c.middlewares, c.transportWrapper))
	if err != nil {
		return nil, fmt.Errorf("could not initialize pinniped client: %w", err)
	}

	return &Client{
		Kubernetes:         k8sClient,
		Aggregation:        aggregatorClient,
		PinnipedConcierge:  pinnipedConciergeClient,
		PinnipedSupervisor: pinnipedSupervisorClient,

		JSONConfig:  jsonKubeConfig,
		ProtoConfig: protoKubeConfig,
	}, nil
}

// Returns a copy of the input config with the ContentConfig set to use json.
// Use this config to communicate with all CRD based APIs.
func createJSONKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	jsonKubeConfig := restclient.CopyConfig(kubeConfig)
	jsonKubeConfig.AcceptContentTypes = runtime.ContentTypeJSON
	jsonKubeConfig.ContentType = runtime.ContentTypeJSON
	return jsonKubeConfig
}

// Returns a copy of the input config with the ContentConfig set to use protobuf.
// Do not use this config to communicate with any CRD based APIs.
func createProtoKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	protoKubeConfig := restclient.CopyConfig(kubeConfig)
	const protoThenJSON = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	protoKubeConfig.AcceptContentTypes = protoThenJSON
	protoKubeConfig.ContentType = runtime.ContentTypeProtobuf
	return protoKubeConfig
}

// createSecureKubeConfig returns a copy of the input config with the WrapTransport
// enhanced to use the secure TLS configuration of the ptls / phttp packages.
func createSecureKubeConfig(kubeConfig *restclient.Config) (*restclient.Config, error) {
	secureKubeConfig := restclient.CopyConfig(kubeConfig)

	// by setting proxy to always be non-nil, we bust the client-go global TLS config cache.
	// this is required to make our wrapper function work without data races.  the unit tests
	// associated with this code run in parallel to assert that we are not using the cache.
	// see k8s.io/client-go/transport.tlsConfigKey
	if secureKubeConfig.Proxy == nil {
		secureKubeConfig.Proxy = net.NewProxierWithNoProxyCIDR(http.ProxyFromEnvironment)
	}

	// make sure restclient.TLSConfigFor always returns a non-nil TLS config
	if len(secureKubeConfig.NextProtos) == 0 {
		secureKubeConfig.NextProtos = ptls.Secure(nil).NextProtos
	}

	tlsConfigTest, err := restclient.TLSConfigFor(secureKubeConfig)
	if err != nil {
		return nil, err // should never happen because our input config should always be valid
	}
	if tlsConfigTest == nil {
		return nil, fmt.Errorf("unexpected empty TLS config") // should never happen because we set NextProtos above
	}

	secureKubeConfig.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		defer func() {
			if err := AssertSecureTransport(rt); err != nil {
				panic(err) // not sure what the point of this function would be if it failed to make the config secure
			}
		}()

		tlsConfig, err := net.TLSClientConfig(rt)
		if err != nil {
			// this assumes none of our production code calls Wrap or messes with WrapTransport.
			// this is a reasonable assumption because all such code should live in this package
			// and all such code should run after this function is called, not before.  the kube
			// codebase uses transport wrappers that can be unwrapped to access the underlying
			// TLS config.
			panic(err)
		}
		if tlsConfig == nil {
			panic("unexpected empty TLS config") // we validate this case above via tlsConfigTest
		}

		// mutate the TLS config into our desired state before it is used
		ptls.Merge(ptls.Secure, tlsConfig)

		return rt // return the input transport since we mutated it in-place
	})

	if err := AssertSecureConfig(secureKubeConfig); err != nil {
		return nil, err // not sure what the point of this function would be if it failed to make the config secure
	}

	return secureKubeConfig, nil
}

// SecureAnonymousClientConfig has the same properties as restclient.AnonymousClientConfig
// while still enforcing the secure TLS configuration of the ptls / phttp packages.
func SecureAnonymousClientConfig(kubeConfig *restclient.Config) *restclient.Config {
	kubeConfig = restclient.AnonymousClientConfig(kubeConfig)
	secureKubeConfig, err := createSecureKubeConfig(kubeConfig)
	if err != nil {
		panic(err) // should never happen as this would only fail on invalid CA data, which would never work anyway
	}
	if err := AssertSecureConfig(secureKubeConfig); err != nil {
		panic(err) // not sure what the point of this function would be if it failed to make the config secure
	}
	return secureKubeConfig
}

func AssertSecureConfig(kubeConfig *restclient.Config) error {
	rt, err := restclient.TransportFor(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed to build transport: %w", err)
	}

	return AssertSecureTransport(rt)
}

func AssertSecureTransport(rt http.RoundTripper) error {
	tlsConfig, err := net.TLSClientConfig(rt)
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}

	tlsConfigCopy := tlsConfig.Clone()
	ptls.Merge(ptls.Secure, tlsConfigCopy) // only mutate the copy

	//nolint: gosec // the empty TLS config here is not used
	if diff := cmp.Diff(tlsConfigCopy, tlsConfig,
		cmpopts.IgnoreUnexported(tls.Config{}, x509.CertPool{}),
		cmpopts.IgnoreFields(tls.Config{}, "GetClientCertificate"),
	); len(diff) != 0 {
		return fmt.Errorf("tls config is not secure:\n%s", diff)
	}

	return nil
}

func Secure(config *restclient.Config) (kubernetes.Interface, *restclient.Config, error) {
	// our middleware does not apply to the returned restclient.Config, therefore, this
	// client not having a leader election lock is irrelevant since it would not be enforced
	secureClient, err := New(WithConfig(config)) // handles nil config correctly
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build secure client: %w", err)
	}
	return secureClient.Kubernetes, secureClient.ProtoConfig, nil
}
