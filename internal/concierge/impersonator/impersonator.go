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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/kubeclient"
)

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
	kubeTransportConfig.TLS.NextProtos = []string{"http/1.1"} // TODO huh?

	kubeRoundTripper, err := transport.New(kubeTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(serverURL)
	reverseProxy.Transport = kubeRoundTripper
	reverseProxy.FlushInterval = 200 * time.Millisecond // the "watch" verb will not work without this line

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

	// Never mutate request (see http.Handler docs).
	newR := r.Clone(r.Context())

	authentication, authenticated, err := bearertoken.New(authenticator.TokenFunc(func(ctx context.Context, token string) (*authenticator.Response, bool, error) {
		tokenCredentialReq, err := extractToken(token, p.jsonDecoder)
		if err != nil {
			log.Error(err, "invalid token encoding")
			return nil, false, &httpError{message: "invalid token encoding", code: http.StatusBadRequest}
		}

		log = log.WithValues(
			"authenticator", tokenCredentialReq.Spec.Authenticator,
		)

		userInfo, err := p.cache.AuthenticateTokenCredentialRequest(newR.Context(), tokenCredentialReq)
		if err != nil {
			log.Error(err, "received invalid token")
			return nil, false, &httpError{message: "invalid token", code: http.StatusUnauthorized}
		}
		if userInfo == nil {
			log.Info("received token that did not authenticate")
			return nil, false, &httpError{message: "not authenticated", code: http.StatusUnauthorized}
		}
		log = log.WithValues("userID", userInfo.GetUID())

		return &authenticator.Response{User: userInfo}, true, nil
	})).AuthenticateRequest(newR)
	if err != nil {
		httpErr, ok := err.(*httpError)
		if !ok {
			log.Error(err, "unrecognized error")
			http.Error(w, "unrecognized error", http.StatusInternalServerError)
		}
		http.Error(w, httpErr.message, httpErr.code)
		return
	}
	if !authenticated {
		log.Error(constable.Error("token authenticator did not find token"), "invalid token encoding")
		http.Error(w, "invalid token encoding", http.StatusBadRequest)
		return
	}

	newR.Header = getProxyHeaders(authentication.User, r.Header)

	log.Info("proxying authenticated request")
	p.proxy.ServeHTTP(w, newR)
}

type httpError struct {
	message string
	code    int
}

func (e *httpError) Error() string { return e.message }

func ensureNoImpersonationHeaders(r *http.Request) error {
	for key := range r.Header {
		if isImpersonationHeader(key) {
			return fmt.Errorf("%q header already exists", key)
		}
	}
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func getProxyHeaders(userInfo user.Info, requestHeaders http.Header) http.Header {
	// Copy over all headers except the Authorization header from the original request to the new request.
	newHeaders := requestHeaders.Clone()
	newHeaders.Del("Authorization")

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
		for headerKey, headerValues := range r.Header {
			if isImpersonationHeader(headerKey) {
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
	return newHeaders
}

func isImpersonationHeader(header string) bool {
	return strings.HasPrefix(http.CanonicalHeaderKey(header), "Impersonate")
}

func extractToken(token string, jsonDecoder runtime.Decoder) (*login.TokenCredentialRequest, error) {
	tokenCredentialRequestJSON, err := base64.StdEncoding.DecodeString(token)
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
