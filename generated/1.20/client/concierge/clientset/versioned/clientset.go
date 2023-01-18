// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package versioned

import (
	"fmt"

	authenticationv1alpha1 "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/typed/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/typed/config/v1alpha1"
	identityv1alpha1 "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/typed/identity/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/typed/login/v1alpha1"
	discovery "k8s.io/client-go/discovery"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
)

type Interface interface {
	Discovery() discovery.DiscoveryInterface
	AuthenticationV1alpha1() authenticationv1alpha1.AuthenticationV1alpha1Interface
	ConfigV1alpha1() configv1alpha1.ConfigV1alpha1Interface
	IdentityV1alpha1() identityv1alpha1.IdentityV1alpha1Interface
	LoginV1alpha1() loginv1alpha1.LoginV1alpha1Interface
}

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*discovery.DiscoveryClient
	authenticationV1alpha1 *authenticationv1alpha1.AuthenticationV1alpha1Client
	configV1alpha1         *configv1alpha1.ConfigV1alpha1Client
	identityV1alpha1       *identityv1alpha1.IdentityV1alpha1Client
	loginV1alpha1          *loginv1alpha1.LoginV1alpha1Client
}

// AuthenticationV1alpha1 retrieves the AuthenticationV1alpha1Client
func (c *Clientset) AuthenticationV1alpha1() authenticationv1alpha1.AuthenticationV1alpha1Interface {
	return c.authenticationV1alpha1
}

// ConfigV1alpha1 retrieves the ConfigV1alpha1Client
func (c *Clientset) ConfigV1alpha1() configv1alpha1.ConfigV1alpha1Interface {
	return c.configV1alpha1
}

// IdentityV1alpha1 retrieves the IdentityV1alpha1Client
func (c *Clientset) IdentityV1alpha1() identityv1alpha1.IdentityV1alpha1Interface {
	return c.identityV1alpha1
}

// LoginV1alpha1 retrieves the LoginV1alpha1Client
func (c *Clientset) LoginV1alpha1() loginv1alpha1.LoginV1alpha1Interface {
	return c.loginV1alpha1
}

// Discovery retrieves the DiscoveryClient
func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	if c == nil {
		return nil
	}
	return c.DiscoveryClient
}

// NewForConfig creates a new Clientset for the given config.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfig will generate a rate-limiter in configShallowCopy.
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		if configShallowCopy.Burst <= 0 {
			return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.authenticationV1alpha1, err = authenticationv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.configV1alpha1, err = configv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.identityV1alpha1, err = identityv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.loginV1alpha1, err = loginv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	cs.DiscoveryClient, err = discovery.NewDiscoveryClientForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.authenticationV1alpha1 = authenticationv1alpha1.NewForConfigOrDie(c)
	cs.configV1alpha1 = configv1alpha1.NewForConfigOrDie(c)
	cs.identityV1alpha1 = identityv1alpha1.NewForConfigOrDie(c)
	cs.loginV1alpha1 = loginv1alpha1.NewForConfigOrDie(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClientForConfigOrDie(c)
	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.authenticationV1alpha1 = authenticationv1alpha1.New(c)
	cs.configV1alpha1 = configv1alpha1.New(c)
	cs.identityV1alpha1 = identityv1alpha1.New(c)
	cs.loginV1alpha1 = loginv1alpha1.New(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClient(c)
	return &cs
}
