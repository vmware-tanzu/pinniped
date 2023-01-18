// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	clientset "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	authenticationv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/authentication/v1alpha1"
	fakeauthenticationv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/authentication/v1alpha1/fake"
	configv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/config/v1alpha1"
	fakeconfigv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/config/v1alpha1/fake"
	identityv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/identity/v1alpha1"
	fakeidentityv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/identity/v1alpha1/fake"
	loginv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/login/v1alpha1"
	fakeloginv1alpha1 "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/typed/login/v1alpha1/fake"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/testing"
)

// NewSimpleClientset returns a clientset that will respond with the provided objects.
// It's backed by a very simple object tracker that processes creates, updates and deletions as-is,
// without applying any validations and/or defaults. It shouldn't be considered a replacement
// for a real clientset and is mostly useful in simple unit tests.
func NewSimpleClientset(objects ...runtime.Object) *Clientset {
	o := testing.NewObjectTracker(scheme, codecs.UniversalDecoder())
	for _, obj := range objects {
		if err := o.Add(obj); err != nil {
			panic(err)
		}
	}

	cs := &Clientset{tracker: o}
	cs.discovery = &fakediscovery.FakeDiscovery{Fake: &cs.Fake}
	cs.AddReactor("*", "*", testing.ObjectReaction(o))
	cs.AddWatchReactor("*", func(action testing.Action) (handled bool, ret watch.Interface, err error) {
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := o.Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		return true, watch, nil
	})

	return cs
}

// Clientset implements clientset.Interface. Meant to be embedded into a
// struct to get a default implementation. This makes faking out just the method
// you want to test easier.
type Clientset struct {
	testing.Fake
	discovery *fakediscovery.FakeDiscovery
	tracker   testing.ObjectTracker
}

func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	return c.discovery
}

func (c *Clientset) Tracker() testing.ObjectTracker {
	return c.tracker
}

var _ clientset.Interface = &Clientset{}

// AuthenticationV1alpha1 retrieves the AuthenticationV1alpha1Client
func (c *Clientset) AuthenticationV1alpha1() authenticationv1alpha1.AuthenticationV1alpha1Interface {
	return &fakeauthenticationv1alpha1.FakeAuthenticationV1alpha1{Fake: &c.Fake}
}

// ConfigV1alpha1 retrieves the ConfigV1alpha1Client
func (c *Clientset) ConfigV1alpha1() configv1alpha1.ConfigV1alpha1Interface {
	return &fakeconfigv1alpha1.FakeConfigV1alpha1{Fake: &c.Fake}
}

// IdentityV1alpha1 retrieves the IdentityV1alpha1Client
func (c *Clientset) IdentityV1alpha1() identityv1alpha1.IdentityV1alpha1Interface {
	return &fakeidentityv1alpha1.FakeIdentityV1alpha1{Fake: &c.Fake}
}

// LoginV1alpha1 retrieves the LoginV1alpha1Client
func (c *Clientset) LoginV1alpha1() loginv1alpha1.LoginV1alpha1Interface {
	return &fakeloginv1alpha1.FakeLoginV1alpha1{Fake: &c.Fake}
}
