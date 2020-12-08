// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package jwtcachefiller implements a controller for filling an authncache.Cache with each
// added/updated JWTAuthenticator.
package jwtcachefiller

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/klog/v2"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	authinformers "go.pinniped.dev/generated/1.19/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
)

// These default values come from the way that the Supervisor issues and signs tokens. We make these
// the defaults for a JWTAuthenticator so that they can easily integrate with the Supervisor.
const (
	defaultUsernameClaim = "sub"
	defaultGroupsClaim   = "groups"
)

// defaultSupportedSigningAlgos returns the default signing algos that this JWTAuthenticator
// supports (i.e., if none are supplied by the user).
func defaultSupportedSigningAlgos() []string {
	return []string{
		// RS256 is recommended by the OIDC spec and required, in some capacity. Since we want the
		// JWTAuthenticator to be able to support many OIDC ID tokens out of the box, we include this
		// algorithm by default.
		string(jose.RS256),
		// ES256 is what the Supervisor does, by default. We want integration with the JWTAuthenticator
		// to be as seamless as possible, so we include this algorithm by default.
		string(jose.ES256),
	}
}

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(
	cache *authncache.Cache,
	jwtAuthenticators authinformers.JWTAuthenticatorInformer,
	log logr.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "jwtcachefiller-controller",
			Syncer: &controller{
				cache:             cache,
				jwtAuthenticators: jwtAuthenticators,
				log:               log.WithName("jwtcachefiller-controller"),
			},
		},
		controllerlib.WithInformer(
			jwtAuthenticators,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

type controller struct {
	cache             *authncache.Cache
	jwtAuthenticators authinformers.JWTAuthenticatorInformer
	log               logr.Logger
}

// Sync implements controllerlib.Syncer.
func (c *controller) Sync(ctx controllerlib.Context) error {
	obj, err := c.jwtAuthenticators.Lister().JWTAuthenticators(ctx.Key.Namespace).Get(ctx.Key.Name)
	if err != nil && errors.IsNotFound(err) {
		c.log.Info("Sync() found that the JWTAuthenticator does not exist yet or was deleted")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get JWTAuthenticator %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	cacheKey := authncache.Key{
		APIGroup:  auth1alpha1.GroupName,
		Kind:      "JWTAuthenticator",
		Namespace: ctx.Key.Namespace,
		Name:      ctx.Key.Name,
	}

	// If this authenticator already exists, then we gotta make sure we close the old authenticator so
	// we don't leak goroutines.
	if value := c.cache.Get(cacheKey); value != nil {
		if closer, ok := value.(authenticator.Closer); ok {
			closer.Close()
		}
	}

	jwtAuthenticator, err := newJWTAuthenticator(&obj.Spec)
	if err != nil {
		return fmt.Errorf("failed to build jwt authenticator: %w", err)
	}

	c.cache.Store(cacheKey, jwtAuthenticator)
	c.log.WithValues("jwtAuthenticator", klog.KObj(obj), "issuer", obj.Spec.Issuer).Info("added new jwt authenticator")
	return nil
}

// newJWTAuthenticator creates a jwt authenticator from the provided spec.
func newJWTAuthenticator(spec *auth1alpha1.JWTAuthenticatorSpec) (*oidc.Authenticator, error) {
	caBundle, err := authenticator.CABundle(spec.TLS)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	var caFile string
	if caBundle != nil {
		temp, err := ioutil.TempFile("", "pinniped-jwkauthenticator-cafile-*")
		if err != nil {
			return nil, fmt.Errorf("unable to create temporary file: %w", err)
		}

		// We can safely remove the temp file at the end of this function since oidc.New() reads the
		// provided CA file and then forgets about it.
		defer func() { _ = os.Remove(temp.Name()) }()

		if _, err := temp.Write(caBundle); err != nil {
			return nil, fmt.Errorf("cannot write CA file: %w", err)
		}

		caFile = temp.Name()
	}

	return oidc.New(oidc.Options{
		IssuerURL:            spec.Issuer,
		ClientID:             spec.Audience,
		UsernameClaim:        defaultUsernameClaim,
		GroupsClaim:          defaultGroupsClaim,
		SupportedSigningAlgs: defaultSupportedSigningAlgos(),
		CAFile:               caFile,
	})
}
