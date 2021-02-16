// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/generated/1.20/apis/concierge/login"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/kubeclient"
)

// allowedHeaders are the set of HTTP headers that are allowed to be forwarded through the impersonation proxy.
//nolint: gochecknoglobals
var allowedHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"User-Agent",
	"Connection",
	"Upgrade",
}

type proxy struct {
	cache       *authncache.Cache
	jsonDecoder runtime.Decoder
	proxy       *httputil.ReverseProxy
	log         logr.Logger
}

func New(cache *authncache.Cache, jsonDecoder runtime.Decoder, log logr.Logger) (http.Handler, error) {
	return newInternal(cache, jsonDecoder, log, func() (*rest.Config, error) {
		client, err := kubeclient.New()
		if err != nil {
			return nil, err
		}
		return client.JSONConfig, nil
	})
}

func newInternal(cache *authncache.Cache, jsonDecoder runtime.Decoder, log logr.Logger, getConfig func() (*rest.Config, error)) (*proxy, error) {
	kubeconfig, err := getConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster config: %w", err)
	}

	serverURL, err := url.Parse(kubeconfig.Host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host URL from in-cluster config: %w", err)
	}

	kubeTransportConfig, err := kubeconfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport config: %w", err)
	}
	kubeTransportConfig.TLS.NextProtos = []string{"http/1.1"}

	kubeRoundTripper, err := transport.New(kubeTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(serverURL)
	reverseProxy.Transport = kubeRoundTripper

	return &proxy{
		cache:       cache,
		jsonDecoder: jsonDecoder,
		proxy:       reverseProxy,
		log:         log,
	}, nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := p.log.WithValues(
		"url", r.URL.String(),
		"method", r.Method,
	)

	if err := ensureNoImpersonationHeaders(r); err != nil {
		log.Error(err, "impersonation header already exists")
		http.Error(w, "impersonation header already exists", http.StatusBadRequest)
		return
	}

	tokenCredentialReq, err := extractToken(r, p.jsonDecoder)
	if err != nil {
		log.Error(err, "invalid token encoding")
		http.Error(w, "invalid token encoding", http.StatusBadRequest)
		return
	}
	log = log.WithValues(
		"authenticator", tokenCredentialReq.Spec.Authenticator,
	)

	userInfo, err := p.cache.AuthenticateTokenCredentialRequest(r.Context(), tokenCredentialReq)
	if err != nil {
		log.Error(err, "received invalid token")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if userInfo == nil {
		log.Info("received token that did not authenticate")
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	log = log.WithValues("userID", userInfo.GetUID())

	// Never mutate request (see http.Handler docs).
	newR := r.WithContext(r.Context())
	newR.Header = getProxyHeaders(userInfo, r.Header)

	log.Info("proxying authenticated request")
	p.proxy.ServeHTTP(w, newR)
}

func ensureNoImpersonationHeaders(r *http.Request) error {
	if _, ok := r.Header[transport.ImpersonateUserHeader]; ok {
		return fmt.Errorf("%q header already exists", transport.ImpersonateUserHeader)
	}

	if _, ok := r.Header[transport.ImpersonateGroupHeader]; ok {
		return fmt.Errorf("%q header already exists", transport.ImpersonateGroupHeader)
	}

	for header := range r.Header {
		if strings.HasPrefix(header, transport.ImpersonateUserExtraHeaderPrefix) {
			return fmt.Errorf("%q header already exists", transport.ImpersonateUserExtraHeaderPrefix)
		}
	}

	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func getProxyHeaders(userInfo user.Info, requestHeaders http.Header) http.Header {
	newHeaders := http.Header{}

	// Leverage client-go's impersonation RoundTripper to set impersonation headers for us in the new
	// request. The client-go RoundTripper not only sets all of the impersonation headers for us, but
	// it also does some helpful escaping of characters that can't go into an HTTP header. To do this,
	// we make a fake call to the impersonation RoundTripper with a fake HTTP request and a delegate
	// RoundTripper that captures the impersonation headers set on the request.
	impersonateConfig := transport.ImpersonationConfig{
		UserName: userInfo.GetName(),
		Groups:   userInfo.GetGroups(),
		Extra:    userInfo.GetExtra(),
	}
	impersonateHeaderSpy := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		newHeaders.Set(transport.ImpersonateUserHeader, r.Header.Get(transport.ImpersonateUserHeader))
		for _, groupHeaderValue := range r.Header.Values(transport.ImpersonateGroupHeader) {
			newHeaders.Add(transport.ImpersonateGroupHeader, groupHeaderValue)
		}
		for headerKey, headerValues := range r.Header {
			if strings.HasPrefix(headerKey, transport.ImpersonateUserExtraHeaderPrefix) {
				for _, headerValue := range headerValues {
					newHeaders.Add(headerKey, headerValue)
				}
			}
		}
		return nil, nil
	})
	fakeReq, _ := http.NewRequestWithContext(context.Background(), "", "", nil)
	//nolint:bodyclose // We return a nil http.Response above, so there is nothing to close.
	_, _ = transport.NewImpersonatingRoundTripper(impersonateConfig, impersonateHeaderSpy).RoundTrip(fakeReq)

	// Copy over the allowed header values from the original request to the new request.
	for _, header := range allowedHeaders {
		values := requestHeaders.Values(header)
		for i := range values {
			newHeaders.Add(header, values[i])
		}
	}

	return newHeaders
}

func extractToken(req *http.Request, jsonDecoder runtime.Decoder) (*login.TokenCredentialRequest, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("authorization header must be of type Bearer")
	}
	encoded := strings.TrimPrefix(authHeader, "Bearer ")
	tokenCredentialRequestJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in encoded bearer token: %w", err)
	}

	obj, err := runtime.Decode(jsonDecoder, tokenCredentialRequestJSON)
	if err != nil {
		return nil, fmt.Errorf("invalid object encoded in bearer token: %w", err)
	}
	tokenCredentialRequest, ok := obj.(*login.TokenCredentialRequest)
	if !ok {
		return nil, fmt.Errorf("invalid TokenCredentialRequest encoded in bearer token: got %T", obj)
	}

	return tokenCredentialRequest, nil
}
