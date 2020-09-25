// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	idpv1alpha1 "go.pinniped.dev/generated/1.18/apis/idp/v1alpha1"
	versioned "go.pinniped.dev/generated/1.18/client/clientset/versioned"
	internalinterfaces "go.pinniped.dev/generated/1.18/client/informers/externalversions/internalinterfaces"
	v1alpha1 "go.pinniped.dev/generated/1.18/client/listers/idp/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// OpenIDConnectIdentityProviderInformer provides access to a shared informer and lister for
// OpenIDConnectIdentityProviders.
type OpenIDConnectIdentityProviderInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.OpenIDConnectIdentityProviderLister
}

type openIDConnectIdentityProviderInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewOpenIDConnectIdentityProviderInformer constructs a new informer for OpenIDConnectIdentityProvider type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewOpenIDConnectIdentityProviderInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredOpenIDConnectIdentityProviderInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredOpenIDConnectIdentityProviderInformer constructs a new informer for OpenIDConnectIdentityProvider type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredOpenIDConnectIdentityProviderInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IDPV1alpha1().OpenIDConnectIdentityProviders(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IDPV1alpha1().OpenIDConnectIdentityProviders(namespace).Watch(context.TODO(), options)
			},
		},
		&idpv1alpha1.OpenIDConnectIdentityProvider{},
		resyncPeriod,
		indexers,
	)
}

func (f *openIDConnectIdentityProviderInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredOpenIDConnectIdentityProviderInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *openIDConnectIdentityProviderInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&idpv1alpha1.OpenIDConnectIdentityProvider{}, f.defaultInformer)
}

func (f *openIDConnectIdentityProviderInformer) Lister() v1alpha1.OpenIDConnectIdentityProviderLister {
	return v1alpha1.NewOpenIDConnectIdentityProviderLister(f.Informer().GetIndexer())
}
