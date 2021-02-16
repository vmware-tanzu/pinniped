// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package cachecleaner implements a controller for garbage collecting authenticators from an authenticator cache.
package cachecleaner

import (
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
)

// New instantiates a new controllerlib.Controller which will garbage collect authenticators from the provided Cache.
func New(
	cache *authncache.Cache,
	webhooks authinformers.WebhookAuthenticatorInformer,
	jwtAuthenticators authinformers.JWTAuthenticatorInformer,
	log logr.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "cachecleaner-controller",
			Syncer: &controller{
				cache:             cache,
				webhooks:          webhooks,
				jwtAuthenticators: jwtAuthenticators,
				log:               log.WithName("cachecleaner-controller"),
			},
		},
		controllerlib.WithInformer(
			webhooks,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		controllerlib.WithInformer(
			jwtAuthenticators,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

type controller struct {
	cache             *authncache.Cache
	webhooks          authinformers.WebhookAuthenticatorInformer
	jwtAuthenticators authinformers.JWTAuthenticatorInformer
	log               logr.Logger
}

// Sync implements controllerlib.Syncer.
func (c *controller) Sync(_ controllerlib.Context) error {
	webhooks, err := c.webhooks.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list WebhookAuthenticators: %w", err)
	}

	jwtAuthenticators, err := c.jwtAuthenticators.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list JWTAuthenticators: %w", err)
	}

	// Index the current authenticators by cache key.
	authenticatorSet := map[authncache.Key]bool{}
	for _, webhook := range webhooks {
		key := authncache.Key{
			Name:     webhook.Name,
			Kind:     "WebhookAuthenticator",
			APIGroup: auth1alpha1.SchemeGroupVersion.Group,
		}
		authenticatorSet[key] = true
	}
	for _, jwtAuthenticator := range jwtAuthenticators {
		key := authncache.Key{
			Name:     jwtAuthenticator.Name,
			Kind:     "JWTAuthenticator",
			APIGroup: auth1alpha1.SchemeGroupVersion.Group,
		}
		authenticatorSet[key] = true
	}

	// Delete any entries from the cache which are no longer in the cluster.
	for _, key := range c.cache.Keys() {
		if key.APIGroup != auth1alpha1.SchemeGroupVersion.Group || (key.Kind != "WebhookAuthenticator" && key.Kind != "JWTAuthenticator") {
			continue
		}
		if _, exists := authenticatorSet[key]; !exists {
			c.log.WithValues(
				"authenticator",
				klog.KRef("", key.Name),
				"kind",
				key.Kind,
			).Info("deleting authenticator from cache")

			value := c.cache.Get(key)
			if closer, ok := value.(authenticator.Closer); ok {
				closer.Close()
			}

			c.cache.Delete(key)
		}
	}
	return nil
}
