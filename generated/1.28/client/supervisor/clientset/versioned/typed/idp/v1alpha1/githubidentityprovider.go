// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "go.pinniped.dev/generated/1.28/apis/supervisor/idp/v1alpha1"
	scheme "go.pinniped.dev/generated/1.28/client/supervisor/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// GitHubIdentityProvidersGetter has a method to return a GitHubIdentityProviderInterface.
// A group's client should implement this interface.
type GitHubIdentityProvidersGetter interface {
	GitHubIdentityProviders(namespace string) GitHubIdentityProviderInterface
}

// GitHubIdentityProviderInterface has methods to work with GitHubIdentityProvider resources.
type GitHubIdentityProviderInterface interface {
	Create(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.CreateOptions) (*v1alpha1.GitHubIdentityProvider, error)
	Update(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.UpdateOptions) (*v1alpha1.GitHubIdentityProvider, error)
	UpdateStatus(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.UpdateOptions) (*v1alpha1.GitHubIdentityProvider, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.GitHubIdentityProvider, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.GitHubIdentityProviderList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.GitHubIdentityProvider, err error)
	GitHubIdentityProviderExpansion
}

// gitHubIdentityProviders implements GitHubIdentityProviderInterface
type gitHubIdentityProviders struct {
	client rest.Interface
	ns     string
}

// newGitHubIdentityProviders returns a GitHubIdentityProviders
func newGitHubIdentityProviders(c *IDPV1alpha1Client, namespace string) *gitHubIdentityProviders {
	return &gitHubIdentityProviders{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the gitHubIdentityProvider, and returns the corresponding gitHubIdentityProvider object, and an error if there is any.
func (c *gitHubIdentityProviders) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.GitHubIdentityProvider, err error) {
	result = &v1alpha1.GitHubIdentityProvider{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of GitHubIdentityProviders that match those selectors.
func (c *gitHubIdentityProviders) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.GitHubIdentityProviderList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.GitHubIdentityProviderList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested gitHubIdentityProviders.
func (c *gitHubIdentityProviders) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a gitHubIdentityProvider and creates it.  Returns the server's representation of the gitHubIdentityProvider, and an error, if there is any.
func (c *gitHubIdentityProviders) Create(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.CreateOptions) (result *v1alpha1.GitHubIdentityProvider, err error) {
	result = &v1alpha1.GitHubIdentityProvider{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(gitHubIdentityProvider).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a gitHubIdentityProvider and updates it. Returns the server's representation of the gitHubIdentityProvider, and an error, if there is any.
func (c *gitHubIdentityProviders) Update(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.UpdateOptions) (result *v1alpha1.GitHubIdentityProvider, err error) {
	result = &v1alpha1.GitHubIdentityProvider{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		Name(gitHubIdentityProvider.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(gitHubIdentityProvider).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *gitHubIdentityProviders) UpdateStatus(ctx context.Context, gitHubIdentityProvider *v1alpha1.GitHubIdentityProvider, opts v1.UpdateOptions) (result *v1alpha1.GitHubIdentityProvider, err error) {
	result = &v1alpha1.GitHubIdentityProvider{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		Name(gitHubIdentityProvider.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(gitHubIdentityProvider).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the gitHubIdentityProvider and deletes it. Returns an error if one occurs.
func (c *gitHubIdentityProviders) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *gitHubIdentityProviders) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("githubidentityproviders").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched gitHubIdentityProvider.
func (c *gitHubIdentityProviders) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.GitHubIdentityProvider, err error) {
	result = &v1alpha1.GitHubIdentityProvider{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("githubidentityproviders").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
