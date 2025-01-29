// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"

	configv1alpha1 "go.pinniped.dev/generated/1.32/apis/supervisor/config/v1alpha1"
	scheme "go.pinniped.dev/generated/1.32/client/supervisor/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// FederationDomainsGetter has a method to return a FederationDomainInterface.
// A group's client should implement this interface.
type FederationDomainsGetter interface {
	FederationDomains(namespace string) FederationDomainInterface
}

// FederationDomainInterface has methods to work with FederationDomain resources.
type FederationDomainInterface interface {
	Create(ctx context.Context, federationDomain *configv1alpha1.FederationDomain, opts v1.CreateOptions) (*configv1alpha1.FederationDomain, error)
	Update(ctx context.Context, federationDomain *configv1alpha1.FederationDomain, opts v1.UpdateOptions) (*configv1alpha1.FederationDomain, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, federationDomain *configv1alpha1.FederationDomain, opts v1.UpdateOptions) (*configv1alpha1.FederationDomain, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*configv1alpha1.FederationDomain, error)
	List(ctx context.Context, opts v1.ListOptions) (*configv1alpha1.FederationDomainList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *configv1alpha1.FederationDomain, err error)
	FederationDomainExpansion
}

// federationDomains implements FederationDomainInterface
type federationDomains struct {
	*gentype.ClientWithList[*configv1alpha1.FederationDomain, *configv1alpha1.FederationDomainList]
}

// newFederationDomains returns a FederationDomains
func newFederationDomains(c *ConfigV1alpha1Client, namespace string) *federationDomains {
	return &federationDomains{
		gentype.NewClientWithList[*configv1alpha1.FederationDomain, *configv1alpha1.FederationDomainList](
			"federationdomains",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *configv1alpha1.FederationDomain { return &configv1alpha1.FederationDomain{} },
			func() *configv1alpha1.FederationDomainList { return &configv1alpha1.FederationDomainList{} },
		),
	}
}
