// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/generated/1.20/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
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

type Proxy struct {
	cache *authncache.Cache
	proxy *httputil.ReverseProxy
	log   logr.Logger
}

func New(cache *authncache.Cache, log logr.Logger) (*Proxy, error) {
	return newInternal(cache, log, rest.InClusterConfig)
}

func newInternal(cache *authncache.Cache, log logr.Logger, getConfig func() (*rest.Config, error)) (*Proxy, error) {
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

	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	proxy.Transport = kubeRoundTripper

	return &Proxy{
		cache: cache,
		proxy: proxy,
		log:   log,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := p.log.WithValues(
		"url", r.URL.String(),
		"method", r.Method,
	)

	tokenCredentialReq, err := extractToken(r)
	if err != nil {
		log.Error(err, "invalid token encoding")
		http.Error(w, "invalid token encoding", http.StatusBadRequest)
		return
	}
	log = log.WithValues(
		"authenticator", tokenCredentialReq.Spec.Authenticator,
		"authenticatorNamespace", tokenCredentialReq.Namespace,
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
	log = log.WithValues(
		"user", userInfo.GetName(),
		"groups", userInfo.GetGroups(),
	)

	newHeaders := getProxyHeaders(userInfo, r.Header)
	r.Header = newHeaders

	log.Info("proxying authenticated request")
	p.proxy.ServeHTTP(w, r)
}

func getProxyHeaders(userInfo user.Info, requestHeaders http.Header) http.Header {
	newHeaders := http.Header{}
	newHeaders.Set("Impersonate-User", userInfo.GetName())
	for _, group := range userInfo.GetGroups() {
		newHeaders.Add("Impersonate-Group", group)
	}
	for _, header := range allowedHeaders {
		values := requestHeaders.Values(header)
		for i := range values {
			newHeaders.Add(header, values[i])
		}
	}
	return newHeaders
}

func extractToken(req *http.Request) (*login.TokenCredentialRequest, error) {
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

	var v1alpha1Req loginv1alpha1.TokenCredentialRequest
	if err := json.Unmarshal(tokenCredentialRequestJSON, &v1alpha1Req); err != nil {
		return nil, fmt.Errorf("invalid TokenCredentialRequest encoded in bearer token: %w", err)
	}
	var internalReq login.TokenCredentialRequest
	if err := loginv1alpha1.Convert_v1alpha1_TokenCredentialRequest_To_login_TokenCredentialRequest(&v1alpha1Req, &internalReq, nil); err != nil {
		return nil, fmt.Errorf("failed to convert v1alpha1 TokenCredentialRequest to internal version: %w", err)
	}
	return &internalReq, nil
}
