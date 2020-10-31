// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachecleaner implements a controller for garbage collecting webhook authenticators from an authenticator cache.
package webhookcachecleaner

import (
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	authinformers "go.pinniped.dev/generated/1.19/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
)

// New instantiates a new controllerlib.Controller which will garbage collect webhooks from the provided Cache.
func New(cache *authncache.Cache, webhooks authinformers.WebhookAuthenticatorInformer, log logr.Logger) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "webhookcachecleaner-controller",
			Syncer: &controller{
				cache:    cache,
				webhooks: webhooks,
				log:      log.WithName("webhookcachecleaner-controller"),
			},
		},
		controllerlib.WithInformer(
			webhooks,
			pinnipedcontroller.MatchAnythingFilter(),
			controllerlib.InformerOption{},
		),
	)
}

type controller struct {
	cache    *authncache.Cache
	webhooks authinformers.WebhookAuthenticatorInformer
	log      logr.Logger
}

// Sync implements controllerlib.Syncer.
func (c *controller) Sync(_ controllerlib.Context) error {
	webhooks, err := c.webhooks.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list WebhookAuthenticators: %w", err)
	}

	// Index the current webhooks by key.
	webhooksByKey := map[controllerlib.Key]*auth1alpha1.WebhookAuthenticator{}
	for _, webhook := range webhooks {
		key := controllerlib.Key{Namespace: webhook.Namespace, Name: webhook.Name}
		webhooksByKey[key] = webhook
	}

	// Delete any entries from the cache which are no longer in the cluster.
	for _, key := range c.cache.Keys() {
		if key.APIGroup != auth1alpha1.SchemeGroupVersion.Group || key.Kind != "WebhookAuthenticator" {
			continue
		}
		if _, exists := webhooksByKey[controllerlib.Key{Namespace: key.Namespace, Name: key.Name}]; !exists {
			c.log.WithValues("webhook", klog.KRef(key.Namespace, key.Name)).Info("deleting webhook authenticator from cache")
			c.cache.Delete(key)
		}
	}
	return nil
}
