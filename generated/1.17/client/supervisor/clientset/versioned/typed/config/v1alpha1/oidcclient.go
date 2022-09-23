// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "go.pinniped.dev/generated/1.17/apis/supervisor/config/v1alpha1"
	scheme "go.pinniped.dev/generated/1.17/client/supervisor/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// OIDCClientsGetter has a method to return a OIDCClientInterface.
// A group's client should implement this interface.
type OIDCClientsGetter interface {
	OIDCClients(namespace string) OIDCClientInterface
}

// OIDCClientInterface has methods to work with OIDCClient resources.
type OIDCClientInterface interface {
	Create(*v1alpha1.OIDCClient) (*v1alpha1.OIDCClient, error)
	Update(*v1alpha1.OIDCClient) (*v1alpha1.OIDCClient, error)
	UpdateStatus(*v1alpha1.OIDCClient) (*v1alpha1.OIDCClient, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.OIDCClient, error)
	List(opts v1.ListOptions) (*v1alpha1.OIDCClientList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.OIDCClient, err error)
	OIDCClientExpansion
}

// oIDCClients implements OIDCClientInterface
type oIDCClients struct {
	client rest.Interface
	ns     string
}

// newOIDCClients returns a OIDCClients
func newOIDCClients(c *ConfigV1alpha1Client, namespace string) *oIDCClients {
	return &oIDCClients{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the oIDCClient, and returns the corresponding oIDCClient object, and an error if there is any.
func (c *oIDCClients) Get(name string, options v1.GetOptions) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of OIDCClients that match those selectors.
func (c *oIDCClients) List(opts v1.ListOptions) (result *v1alpha1.OIDCClientList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.OIDCClientList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("oidcclients").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested oIDCClients.
func (c *oIDCClients) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("oidcclients").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a oIDCClient and creates it.  Returns the server's representation of the oIDCClient, and an error, if there is any.
func (c *oIDCClients) Create(oIDCClient *v1alpha1.OIDCClient) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("oidcclients").
		Body(oIDCClient).
		Do().
		Into(result)
	return
}

// Update takes the representation of a oIDCClient and updates it. Returns the server's representation of the oIDCClient, and an error, if there is any.
func (c *oIDCClients) Update(oIDCClient *v1alpha1.OIDCClient) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(oIDCClient.Name).
		Body(oIDCClient).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *oIDCClients) UpdateStatus(oIDCClient *v1alpha1.OIDCClient) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(oIDCClient.Name).
		SubResource("status").
		Body(oIDCClient).
		Do().
		Into(result)
	return
}

// Delete takes name of the oIDCClient and deletes it. Returns an error if one occurs.
func (c *oIDCClients) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *oIDCClients) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("oidcclients").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched oIDCClient.
func (c *oIDCClients) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("oidcclients").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
