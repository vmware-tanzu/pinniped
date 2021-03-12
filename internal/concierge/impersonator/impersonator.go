// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

// FactoryFunc is a function which can create an impersonator server.
// It returns a function which will start the impersonator server.
// That start function takes a stopCh which can be used to stop the server.
// Once a server has been stopped, don't start it again using the start function.
// Instead, call the factory function again to get a new start function.
type FactoryFunc func(
	port int,
	dynamicCertProvider dynamiccert.Private,
	impersonationProxySignerCA dynamiccert.Public,
) (func(stopCh <-chan struct{}) error, error)

func New(
	port int,
	dynamicCertProvider dynamiccert.Private,
	impersonationProxySignerCA dynamiccert.Public,
) (func(stopCh <-chan struct{}) error, error) {
	return newInternal(port, dynamicCertProvider, impersonationProxySignerCA, nil, nil)
}

func newInternal( //nolint:funlen // yeah, it's kind of long.
	port int,
	dynamicCertProvider dynamiccert.Private,
	impersonationProxySignerCA dynamiccert.Public,
	clientOpts []kubeclient.Option, // for unit testing, should always be nil in production
	recOpts func(*genericoptions.RecommendedOptions), // for unit testing, should always be nil in production
) (func(stopCh <-chan struct{}) error, error) {
	var listener net.Listener

	constructServer := func() (func(stopCh <-chan struct{}) error, error) {
		// Bare minimum server side scheme to allow for status messages to be encoded.
		scheme := runtime.NewScheme()
		metav1.AddToGroupVersion(scheme, metav1.Unversioned)
		codecs := serializer.NewCodecFactory(scheme)

		// This is unused for now but it is a safe value that we could use in the future.
		defaultEtcdPathPrefix := "/pinniped-impersonation-proxy-registry"

		recommendedOptions := genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			codecs.LegacyCodec(),
		)
		recommendedOptions.Etcd = nil                                                   // turn off etcd storage because we don't need it yet
		recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertProvider // serving certs (end user facing)
		recommendedOptions.SecureServing.BindPort = port

		// Wire up the impersonation proxy signer CA as another valid authenticator for client cert auth,
		// along with the Kube API server's CA.
		kubeClient, err := kubeclient.New(clientOpts...)
		if err != nil {
			return nil, err
		}
		kubeClientCA, err := dynamiccertificates.NewDynamicCAFromConfigMapController(
			"client-ca", metav1.NamespaceSystem, "extension-apiserver-authentication", "client-ca-file", kubeClient.Kubernetes,
		)
		if err != nil {
			return nil, err
		}
		recommendedOptions.Authentication.ClientCert.ClientCA = "---irrelevant-but-needs-to-be-non-empty---" // drop when we pick up https://github.com/kubernetes/kubernetes/pull/100055
		recommendedOptions.Authentication.ClientCert.CAContentProvider = dynamiccertificates.NewUnionCAContentProvider(
			impersonationProxySignerCA, kubeClientCA,
		)

		if recOpts != nil {
			recOpts(recommendedOptions)
		}

		serverConfig := genericapiserver.NewRecommendedConfig(codecs)

		// Note that ApplyTo is going to create a network listener and bind to the requested port.
		// It puts this listener into serverConfig.SecureServing.Listener.
		err = recommendedOptions.ApplyTo(serverConfig)
		if serverConfig.SecureServing != nil {
			// Set the pointer from the outer function to allow the outer function to close the listener in case
			// this function returns an error for any reason anywhere below here.
			listener = serverConfig.SecureServing.Listener
		}
		if err != nil {
			return nil, err
		}

		// Loopback authentication to this server does not really make sense since we just proxy everything to
		// the Kube API server, thus we replace loopback connection config with one that does direct connections
		// the Kube API server. Loopback config is mainly used by post start hooks, so this is mostly future proofing.
		serverConfig.LoopbackClientConfig = rest.CopyConfig(kubeClient.ProtoConfig) // assume proto is safe (hooks can override)
		// Remove the bearer token so our authorizer does not get stomped on by AuthorizeClientBearerToken.
		// See sanity checks at the end of this function.
		serverConfig.LoopbackClientConfig.BearerToken = ""

		// Assume proto config is safe because transport level configs do not use rest.ContentConfig.
		// Thus if we are interacting with actual APIs, they should be using pre-built clients.
		impersonationProxy, err := newImpersonationReverseProxy(rest.CopyConfig(kubeClient.ProtoConfig))
		if err != nil {
			return nil, err
		}

		defaultBuildHandlerChainFunc := serverConfig.BuildHandlerChainFunc
		serverConfig.BuildHandlerChainFunc = func(_ http.Handler, c *genericapiserver.Config) http.Handler {
			// We ignore the passed in handler because we never have any REST APIs to delegate to.
			handler := defaultBuildHandlerChainFunc(impersonationProxy, c)
			handler = securityheader.Wrap(handler)
			return handler
		}

		// Overwrite the delegating authorizer with one that only cares about impersonation.
		// Empty string is disallowed because request info has had bugs in the past where it would leave it empty.
		disallowedVerbs := sets.NewString("", "impersonate")
		noImpersonationAuthorizer := &comparableAuthorizer{
			AuthorizerFunc: func(a authorizer.Attributes) (authorizer.Decision, string, error) {
				// Supporting impersonation is not hard, it would just require a bunch of testing
				// and configuring the audit layer (to preserve the caller) which we can do later.
				// We would also want to delete the incoming impersonation headers
				// instead of overwriting the delegating authorizer, we would
				// actually use it to make the impersonation authorization checks.
				if disallowedVerbs.Has(a.GetVerb()) {
					return authorizer.DecisionDeny, "impersonation is not allowed or invalid verb", nil
				}

				return authorizer.DecisionAllow, "deferring authorization to kube API server", nil
			},
		}
		// Set our custom authorizer before calling Compete(), which will use it.
		serverConfig.Authorization.Authorizer = noImpersonationAuthorizer

		impersonationProxyServer, err := serverConfig.Complete().New("impersonation-proxy", genericapiserver.NewEmptyDelegate())
		if err != nil {
			return nil, err
		}

		preparedRun := impersonationProxyServer.PrepareRun()

		// Sanity check. Make sure that our custom authorizer is still in place and did not get changed or wrapped.
		if preparedRun.Authorizer != noImpersonationAuthorizer {
			return nil, constable.Error("invalid mutation of impersonation authorizer detected")
		}

		// Sanity check. Assert that we have a functioning token file to use and no bearer token.
		if len(preparedRun.LoopbackClientConfig.BearerToken) != 0 || len(preparedRun.LoopbackClientConfig.BearerTokenFile) == 0 {
			return nil, constable.Error("invalid impersonator loopback rest config has wrong bearer token semantics")
		}

		return preparedRun.Run, nil
	}

	result, err := constructServer()
	// If there was any error during construction, then we would like to close the listener to free up the port.
	if err != nil {
		errs := []error{err}
		if listener != nil {
			errs = append(errs, listener.Close())
		}
		return nil, errors.NewAggregate(errs)
	}
	return result, nil
}

// No-op wrapping around AuthorizerFunc to allow for comparisons.
type comparableAuthorizer struct {
	authorizer.AuthorizerFunc
}

func newImpersonationReverseProxy(restConfig *rest.Config) (http.Handler, error) {
	serverURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host URL from in-cluster config: %w", err)
	}

	kubeTransportConfig, err := restConfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport config: %w", err)
	}
	kubeTransportConfig.TLS.NextProtos = []string{"http/1.1"} // TODO huh?

	kubeRoundTripper, err := transport.New(kubeTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport: %w", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) != 0 {
			plog.Warning("aggregated API server logic did not delete authorization header but it is always supposed to do so",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid authorization header", http.StatusInternalServerError)
			return
		}

		if err := ensureNoImpersonationHeaders(r); err != nil {
			plog.Error("noImpersonationAuthorizer logic did not prevent nested impersonation but it is always supposed to do so",
				err,
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid impersonation", http.StatusInternalServerError)
			return
		}

		userInfo, ok := request.UserFrom(r.Context())
		if !ok {
			plog.Warning("aggregated API server logic did not set user info but it is always supposed to do so",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "invalid user", http.StatusInternalServerError)
			return
		}

		if len(userInfo.GetUID()) > 0 {
			plog.Warning("rejecting request with UID since we cannot impersonate UIDs",
				"url", r.URL.String(),
				"method", r.Method,
			)
			http.Error(w, "unexpected uid", http.StatusUnprocessableEntity)
			return
		}

		plog.Trace("proxying authenticated request",
			"url", r.URL.String(),
			"method", r.Method,
			"username", userInfo.GetName(), // this info leak seems fine for trace level logs
		)

		reverseProxy := httputil.NewSingleHostReverseProxy(serverURL)
		impersonateConfig := transport.ImpersonationConfig{
			UserName: userInfo.GetName(),
			Groups:   userInfo.GetGroups(),
			Extra:    userInfo.GetExtra(),
		}
		reverseProxy.Transport = transport.NewImpersonatingRoundTripper(impersonateConfig, kubeRoundTripper)
		reverseProxy.FlushInterval = 200 * time.Millisecond // the "watch" verb will not work without this line
		// transport.NewImpersonatingRoundTripper clones the request before setting headers
		// so this call will not accidentally mutate the input request (see http.Handler docs)
		reverseProxy.ServeHTTP(w, r)
	}), nil
}

func ensureNoImpersonationHeaders(r *http.Request) error {
	for key := range r.Header {
		if strings.HasPrefix(key, "Impersonate") {
			return fmt.Errorf("%q header already exists", key)
		}
	}

	return nil
}
