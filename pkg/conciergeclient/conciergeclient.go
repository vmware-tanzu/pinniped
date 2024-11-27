// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package conciergeclient provides login helpers for the Pinniped concierge.
package conciergeclient

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
)

// ErrLoginFailed is returned by Client.ExchangeToken when the concierge server rejects the login request for any reason.
const ErrLoginFailed = constable.Error("login failed")

// Option is an optional configuration for New().
type Option func(*Client) error

// Client is a configuration for talking to the Pinniped concierge.
type Client struct {
	authenticator    *corev1.TypedLocalObjectReference
	caBundle         string
	endpoint         *url.URL
	apiGroupSuffix   string
	transportWrapper transport.WrapperFunc
}

// WithAuthenticator configures the authenticator reference (spec.authenticator) of the TokenCredentialRequests.
func WithAuthenticator(authType, authName string) Option {
	return func(c *Client) error {
		if authName == "" {
			return fmt.Errorf("authenticator name must not be empty")
		}
		authenticator := corev1.TypedLocalObjectReference{Name: authName}
		switch strings.ToLower(authType) {
		case "webhook":
			authenticator.APIGroup = &authenticationv1alpha1.SchemeGroupVersion.Group
			authenticator.Kind = "WebhookAuthenticator"
		case "jwt":
			authenticator.APIGroup = &authenticationv1alpha1.SchemeGroupVersion.Group
			authenticator.Kind = "JWTAuthenticator"
		default:
			return fmt.Errorf(`invalid authenticator type: %q, supported values are "webhook" and "jwt"`, authType)
		}
		c.authenticator = &authenticator
		return nil
	}
}

// WithCABundle configures the PEM-formatted TLS certificate authority to trust when connecting to the concierge.
func WithCABundle(caBundle string) Option {
	return func(c *Client) error {
		if caBundle == "" {
			return nil
		}
		if p := x509.NewCertPool(); !p.AppendCertsFromPEM([]byte(caBundle)) {
			return fmt.Errorf("invalid CA bundle data: no certificates found")
		}
		c.caBundle = caBundle
		return nil
	}
}

// WithBase64CABundle configures the base64-encoded, PEM-formatted TLS certificate authority to trust when connecting to the concierge.
func WithBase64CABundle(caBundleBase64 string) Option {
	return func(c *Client) error {
		caBundle, err := base64.StdEncoding.DecodeString(caBundleBase64)
		if err != nil {
			return fmt.Errorf("invalid CA bundle data: %w", err)
		}
		return WithCABundle(string(caBundle))(c)
	}
}

// WithEndpoint configures the base API endpoint URL of the concierge service (same as Kubernetes API server).
func WithEndpoint(endpoint string) Option {
	return func(c *Client) error {
		if endpoint == "" {
			return fmt.Errorf("endpoint must not be empty")
		}
		u, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint URL: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf(`invalid endpoint scheme %q (must be "https")`, u.Scheme)
		}
		c.endpoint = u
		return nil
	}
}

// WithAPIGroupSuffix configures the concierge's API group suffix (e.g., "pinniped.dev").
func WithAPIGroupSuffix(apiGroupSuffix string) Option {
	return func(c *Client) error {
		if err := groupsuffix.Validate(apiGroupSuffix); err != nil {
			return fmt.Errorf("invalid API group suffix: %w", err)
		}
		c.apiGroupSuffix = apiGroupSuffix
		return nil
	}
}

func WithTransportWrapper(wrapper transport.WrapperFunc) Option {
	return func(c *Client) error {
		if wrapper == nil {
			return fmt.Errorf("transport wrapper cannot be nil")
		}
		c.transportWrapper = wrapper
		return nil
	}
}

// New validates the specified options and returns a newly initialized *Client.
func New(opts ...Option) (*Client, error) {
	c := Client{apiGroupSuffix: groupsuffix.PinnipedDefaultSuffix}
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}
	if c.authenticator == nil {
		return nil, fmt.Errorf("WithAuthenticator must be specified")
	}
	if c.endpoint == nil {
		return nil, fmt.Errorf("WithEndpoint must be specified")
	}
	return &c, nil
}

// clientset returns an anonymous client for the concierge API.
func (c *Client) clientset() (conciergeclientset.Interface, error) {
	cfg, err := clientcmd.NewNonInteractiveClientConfig(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {
				Server:                   c.endpoint.String(),
				CertificateAuthorityData: []byte(c.caBundle),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"current": {
				Cluster:  "cluster",
				AuthInfo: "client",
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"client": {},
		},
	}, "current", &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubeclient.New(
		kubeclient.WithConfig(cfg),
		kubeclient.WithMiddleware(groupsuffix.New(c.apiGroupSuffix)),
		kubeclient.WithTransportWrapper(c.transportWrapper),
	)
	if err != nil {
		return nil, err
	}
	return client.PinnipedConcierge, nil
}

// ExchangeToken performs a TokenCredentialRequest against the Pinniped concierge and returns the result as an ExecCredential.
func (c *Client) ExchangeToken(ctx context.Context, token string) (*clientauthenticationv1beta1.ExecCredential, error) {
	clientset, err := c.clientset()
	if err != nil {
		return nil, err
	}
	resp, err := clientset.LoginV1alpha1().TokenCredentialRequests().Create(ctx, &loginv1alpha1.TokenCredentialRequest{
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token:         token,
			Authenticator: *c.authenticator,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not login: %w", err)
	}
	if resp.Status.Credential == nil || resp.Status.Message != nil {
		if resp.Status.Message != nil {
			return nil, fmt.Errorf("%w: %s", ErrLoginFailed, *resp.Status.Message)
		}
		return nil, fmt.Errorf("%w: unknown cause", ErrLoginFailed)
	}

	return &clientauthenticationv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthenticationv1beta1.ExecCredentialStatus{
			ExpirationTimestamp:   &resp.Status.Credential.ExpirationTimestamp,
			ClientCertificateData: resp.Status.Credential.ClientCertificateData,
			ClientKeyData:         resp.Status.Credential.ClientKeyData,
			Token:                 resp.Status.Credential.Token,
		},
	}, nil
}
