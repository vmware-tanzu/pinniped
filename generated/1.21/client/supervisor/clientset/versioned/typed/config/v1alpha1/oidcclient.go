// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "go.pinniped.dev/generated/1.21/apis/supervisor/config/v1alpha1"
	scheme "go.pinniped.dev/generated/1.21/client/supervisor/clientset/versioned/scheme"
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
	Create(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.CreateOptions) (*v1alpha1.OIDCClient, error)
	Update(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.UpdateOptions) (*v1alpha1.OIDCClient, error)
	UpdateStatus(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.UpdateOptions) (*v1alpha1.OIDCClient, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.OIDCClient, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.OIDCClientList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.OIDCClient, err error)
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
func (c *oIDCClients) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of OIDCClients that match those selectors.
func (c *oIDCClients) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.OIDCClientList, err error) {
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
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested oIDCClients.
func (c *oIDCClients) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
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
		Watch(ctx)
}

// Create takes the representation of a oIDCClient and creates it.  Returns the server's representation of the oIDCClient, and an error, if there is any.
func (c *oIDCClients) Create(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.CreateOptions) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("oidcclients").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(oIDCClient).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a oIDCClient and updates it. Returns the server's representation of the oIDCClient, and an error, if there is any.
func (c *oIDCClients) Update(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.UpdateOptions) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(oIDCClient.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(oIDCClient).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *oIDCClients) UpdateStatus(ctx context.Context, oIDCClient *v1alpha1.OIDCClient, opts v1.UpdateOptions) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(oIDCClient.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(oIDCClient).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the oIDCClient and deletes it. Returns an error if one occurs.
func (c *oIDCClients) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("oidcclients").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *oIDCClients) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("oidcclients").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched oIDCClient.
func (c *oIDCClients) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.OIDCClient, err error) {
	result = &v1alpha1.OIDCClient{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("oidcclients").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
