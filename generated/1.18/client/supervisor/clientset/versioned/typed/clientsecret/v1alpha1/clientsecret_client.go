// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/1.18/apis/supervisor/clientsecret/v1alpha1"
	"go.pinniped.dev/generated/1.18/client/supervisor/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type ClientsecretV1alpha1Interface interface {
	RESTClient() rest.Interface
	OIDCClientSecretRequestsGetter
}

// ClientsecretV1alpha1Client is used to interact with features provided by the clientsecret.supervisor.pinniped.dev group.
type ClientsecretV1alpha1Client struct {
	restClient rest.Interface
}

func (c *ClientsecretV1alpha1Client) OIDCClientSecretRequests(namespace string) OIDCClientSecretRequestInterface {
	return newOIDCClientSecretRequests(c, namespace)
}

// NewForConfig creates a new ClientsecretV1alpha1Client for the given config.
func NewForConfig(c *rest.Config) (*ClientsecretV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &ClientsecretV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new ClientsecretV1alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *ClientsecretV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new ClientsecretV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *ClientsecretV1alpha1Client {
	return &ClientsecretV1alpha1Client{c}
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
func (c *ClientsecretV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
