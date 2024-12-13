// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"
	time "time"

	conciergeauthenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	versioned "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	internalinterfaces "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/internalinterfaces"
	authenticationv1alpha1 "go.pinniped.dev/generated/latest/client/concierge/listers/authentication/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// JWTAuthenticatorInformer provides access to a shared informer and lister for
// JWTAuthenticators.
type JWTAuthenticatorInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() authenticationv1alpha1.JWTAuthenticatorLister
}

type jWTAuthenticatorInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewJWTAuthenticatorInformer constructs a new informer for JWTAuthenticator type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewJWTAuthenticatorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredJWTAuthenticatorInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredJWTAuthenticatorInformer constructs a new informer for JWTAuthenticator type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredJWTAuthenticatorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AuthenticationV1alpha1().JWTAuthenticators().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AuthenticationV1alpha1().JWTAuthenticators().Watch(context.TODO(), options)
			},
		},
		&conciergeauthenticationv1alpha1.JWTAuthenticator{},
		resyncPeriod,
		indexers,
	)
}

func (f *jWTAuthenticatorInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredJWTAuthenticatorInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *jWTAuthenticatorInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&conciergeauthenticationv1alpha1.JWTAuthenticator{}, f.defaultInformer)
}

func (f *jWTAuthenticatorInformer) Lister() authenticationv1alpha1.JWTAuthenticatorLister {
	return authenticationv1alpha1.NewJWTAuthenticatorLister(f.Informer().GetIndexer())
}
