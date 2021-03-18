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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/filters"
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
		// Note: any changes to the the Authentication stack need to be kept in sync with any assumptions made
		// by getTransportForUser, especially if we ever update the TCR API to start returning bearer tokens.
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

		// match KAS exactly since our long running operations are just a proxy to it
		// this must be kept in sync with github.com/kubernetes/kubernetes/cmd/kube-apiserver/app/server.go
		// this is nothing to stress about - it has not changed since the beginning of Kube:
		// v1.6 no-op move away from regex to request info https://github.com/kubernetes/kubernetes/pull/38119
		// v1.1 added pods/attach to the list https://github.com/kubernetes/kubernetes/pull/13705
		serverConfig.LongRunningFunc = filters.BasicLongRunningRequestCheck(
			sets.NewString("watch", "proxy"),
			sets.NewString("attach", "exec", "proxy", "log", "portforward"),
		)

		// Assume proto config is safe because transport level configs do not use rest.ContentConfig.
		// Thus if we are interacting with actual APIs, they should be using pre-built clients.
		impersonationProxyFunc, err := newImpersonationReverseProxyFunc(rest.CopyConfig(kubeClient.ProtoConfig))
		if err != nil {
			return nil, err
		}

		defaultBuildHandlerChainFunc := serverConfig.BuildHandlerChainFunc
		serverConfig.BuildHandlerChainFunc = func(_ http.Handler, c *genericapiserver.Config) http.Handler {
			// We ignore the passed in handler because we never have any REST APIs to delegate to.
			handler := impersonationProxyFunc(c)
			handler = defaultBuildHandlerChainFunc(handler, c)
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

func newImpersonationReverseProxyFunc(restConfig *rest.Config) (func(*genericapiserver.Config) http.Handler, error) {
	serverURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host URL from in-cluster config: %w", err)
	}

	http1RoundTripper, err := getTransportForProtocol(restConfig, "http/1.1")
	if err != nil {
		return nil, fmt.Errorf("could not get http/1.1 round tripper: %w", err)
	}

	http2RoundTripper, err := getTransportForProtocol(restConfig, "h2")
	if err != nil {
		return nil, fmt.Errorf("could not get http/2.0 round tripper: %w", err)
	}

	return func(c *genericapiserver.Config) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Values("Authorization")) != 0 {
				plog.Warning("aggregated API server logic did not delete authorization header but it is always supposed to do so",
					"url", r.URL.String(),
					"method", r.Method,
				)
				newInternalErrResponse(w, r, c.Serializer, "invalid authorization header")
				return
			}

			if err := ensureNoImpersonationHeaders(r); err != nil {
				plog.Error("noImpersonationAuthorizer logic did not prevent nested impersonation but it is always supposed to do so",
					err,
					"url", r.URL.String(),
					"method", r.Method,
				)
				newInternalErrResponse(w, r, c.Serializer, "invalid impersonation")
				return
			}

			userInfo, ok := request.UserFrom(r.Context())
			if !ok {
				plog.Warning("aggregated API server logic did not set user info but it is always supposed to do so",
					"url", r.URL.String(),
					"method", r.Method,
				)
				newInternalErrResponse(w, r, c.Serializer, "invalid user")
				return
			}

			reqInfo, ok := request.RequestInfoFrom(r.Context())
			if !ok {
				plog.Warning("aggregated API server logic did not set request info but it is always supposed to do so",
					"url", r.URL.String(),
					"method", r.Method,
				)
				newInternalErrResponse(w, r, c.Serializer, "invalid request info")
				return
			}

			// when we are running regular requests (e.g., CRUD) we should always be able to use HTTP/2.0
			// since KAS always supports that and it goes through proxies just fine. for long running
			// requests (e.g., proxy, watch), we know they use http/1.1 with an upgrade to
			// websockets/SPDY (this upgrade is NEVER to HTTP/2.0 as the KAS does not support that).
			baseRT := http2RoundTripper
			if c.LongRunningFunc(r, reqInfo) {
				baseRT = http1RoundTripper
			}

			rt, err := getTransportForUser(userInfo, baseRT)
			if err != nil {
				plog.WarningErr("rejecting request as we cannot act as the current user", err,
					"url", r.URL.String(),
					"method", r.Method,
				)
				newInternalErrResponse(w, r, c.Serializer, "unimplemented functionality - unable to act as current user")
				return
			}

			plog.Debug("impersonation proxy servicing request", "method", r.Method, "url", r.URL.String())
			plog.Trace("impersonation proxy servicing request was for user", "method", r.Method, "url", r.URL.String(),
				"username", userInfo.GetName(), // this info leak seems fine for trace level logs
			)

			// The proxy library used below will panic when the client disconnects abruptly, so in order to
			// assure that this log message is always printed at the end of this func, it must be deferred.
			defer plog.Debug("impersonation proxy finished servicing request", "method", r.Method, "url", r.URL.String())

			reverseProxy := httputil.NewSingleHostReverseProxy(serverURL)
			reverseProxy.Transport = rt
			reverseProxy.FlushInterval = 200 * time.Millisecond // the "watch" verb will not work without this line
			reverseProxy.ServeHTTP(w, r)
		})
	}, nil
}

func ensureNoImpersonationHeaders(r *http.Request) error {
	for key := range r.Header {
		if strings.HasPrefix(key, "Impersonate") {
			return fmt.Errorf("%q header already exists", key)
		}
	}

	return nil
}

func getTransportForUser(userInfo user.Info, delegate http.RoundTripper) (http.RoundTripper, error) {
	if len(userInfo.GetUID()) == 0 {
		impersonateConfig := transport.ImpersonationConfig{
			UserName: userInfo.GetName(),
			Groups:   userInfo.GetGroups(),
			Extra:    userInfo.GetExtra(),
		}
		// transport.NewImpersonatingRoundTripper clones the request before setting headers
		// thus it will not accidentally mutate the input request (see http.Handler docs)
		return transport.NewImpersonatingRoundTripper(impersonateConfig, delegate), nil
	}

	// 0. in the case of a request that is not attempting to do nested impersonation
	// 1. if we make the assumption that the TCR API does not issue tokens (or pass the TCR API bearer token
	//    authenticator into this func - we need to know the authentication cred is something KAS would honor)
	// 2. then if preserve the incoming authorization header into the request's context
	// 3. we could reauthenticate it here (it would be a free cache hit)
	// 4. confirm that it matches the passed in user info (i.e. it was actually the cred used to authenticate and not a client cert)
	// 5. then we could issue a reverse proxy request using an anonymous rest config and the bearer token
	// 6. thus instead of impersonating the user, we would just be passing their request through
	// 7. this would preserve the UID info and thus allow us to safely support all token based auth
	// 8. the above would be safe even if in the future Kube started supporting UIDs asserted by client certs
	return nil, constable.Error("unexpected uid")
}

func newInternalErrResponse(w http.ResponseWriter, r *http.Request, s runtime.NegotiatedSerializer, msg string) {
	newStatusErrResponse(w, r, s, apierrors.NewInternalError(constable.Error(msg)))
}

func newStatusErrResponse(w http.ResponseWriter, r *http.Request, s runtime.NegotiatedSerializer, err *apierrors.StatusError) {
	requestInfo, ok := genericapirequest.RequestInfoFrom(r.Context())
	if !ok {
		responsewriters.InternalError(w, r, constable.Error("no RequestInfo found in the context"))
		return
	}

	gv := schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}
	responsewriters.ErrorNegotiated(err, s, gv, w, r)
}

func getTransportForProtocol(restConfig *rest.Config, protocol string) (http.RoundTripper, error) {
	transportConfig, err := restConfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport config: %w", err)
	}
	transportConfig.TLS.NextProtos = []string{protocol}

	return transport.New(transportConfig)
}
