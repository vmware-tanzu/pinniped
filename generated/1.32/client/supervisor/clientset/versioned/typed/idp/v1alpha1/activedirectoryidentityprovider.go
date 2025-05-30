// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"

	idpv1alpha1 "go.pinniped.dev/generated/1.32/apis/supervisor/idp/v1alpha1"
	scheme "go.pinniped.dev/generated/1.32/client/supervisor/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// ActiveDirectoryIdentityProvidersGetter has a method to return a ActiveDirectoryIdentityProviderInterface.
// A group's client should implement this interface.
type ActiveDirectoryIdentityProvidersGetter interface {
	ActiveDirectoryIdentityProviders(namespace string) ActiveDirectoryIdentityProviderInterface
}

// ActiveDirectoryIdentityProviderInterface has methods to work with ActiveDirectoryIdentityProvider resources.
type ActiveDirectoryIdentityProviderInterface interface {
	Create(ctx context.Context, activeDirectoryIdentityProvider *idpv1alpha1.ActiveDirectoryIdentityProvider, opts v1.CreateOptions) (*idpv1alpha1.ActiveDirectoryIdentityProvider, error)
	Update(ctx context.Context, activeDirectoryIdentityProvider *idpv1alpha1.ActiveDirectoryIdentityProvider, opts v1.UpdateOptions) (*idpv1alpha1.ActiveDirectoryIdentityProvider, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, activeDirectoryIdentityProvider *idpv1alpha1.ActiveDirectoryIdentityProvider, opts v1.UpdateOptions) (*idpv1alpha1.ActiveDirectoryIdentityProvider, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*idpv1alpha1.ActiveDirectoryIdentityProvider, error)
	List(ctx context.Context, opts v1.ListOptions) (*idpv1alpha1.ActiveDirectoryIdentityProviderList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *idpv1alpha1.ActiveDirectoryIdentityProvider, err error)
	ActiveDirectoryIdentityProviderExpansion
}

// activeDirectoryIdentityProviders implements ActiveDirectoryIdentityProviderInterface
type activeDirectoryIdentityProviders struct {
	*gentype.ClientWithList[*idpv1alpha1.ActiveDirectoryIdentityProvider, *idpv1alpha1.ActiveDirectoryIdentityProviderList]
}

// newActiveDirectoryIdentityProviders returns a ActiveDirectoryIdentityProviders
func newActiveDirectoryIdentityProviders(c *IDPV1alpha1Client, namespace string) *activeDirectoryIdentityProviders {
	return &activeDirectoryIdentityProviders{
		gentype.NewClientWithList[*idpv1alpha1.ActiveDirectoryIdentityProvider, *idpv1alpha1.ActiveDirectoryIdentityProviderList](
			"activedirectoryidentityproviders",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *idpv1alpha1.ActiveDirectoryIdentityProvider {
				return &idpv1alpha1.ActiveDirectoryIdentityProvider{}
			},
			func() *idpv1alpha1.ActiveDirectoryIdentityProviderList {
				return &idpv1alpha1.ActiveDirectoryIdentityProviderList{}
			},
		),
	}
}
