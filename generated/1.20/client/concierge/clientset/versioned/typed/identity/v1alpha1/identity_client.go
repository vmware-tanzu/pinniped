// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/identity/v1alpha1"
	"go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type IdentityV1alpha1Interface interface {
	RESTClient() rest.Interface
	WhoAmIRequestsGetter
}

// IdentityV1alpha1Client is used to interact with features provided by the identity.concierge.pinniped.dev group.
type IdentityV1alpha1Client struct {
	restClient rest.Interface
}

func (c *IdentityV1alpha1Client) WhoAmIRequests() WhoAmIRequestInterface {
	return newWhoAmIRequests(c)
}

// NewForConfig creates a new IdentityV1alpha1Client for the given config.
func NewForConfig(c *rest.Config) (*IdentityV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &IdentityV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new IdentityV1alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *IdentityV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new IdentityV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *IdentityV1alpha1Client {
	return &IdentityV1alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v1alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *IdentityV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
