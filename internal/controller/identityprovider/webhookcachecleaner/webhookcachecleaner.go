// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachecleaner implements a controller for garbage collectting webhook IDPs from an IDP cache.
package webhookcachecleaner

import (
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	idpv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/idp/v1alpha1"
	idpinformers "github.com/suzerain-io/pinniped/generated/1.19/client/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	"github.com/suzerain-io/pinniped/internal/controller/identityprovider/idpcache"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
)

// New instantiates a new controllerlib.Controller which will garbage collect webhooks from the provided Cache.
func New(cache *idpcache.Cache, webhookIDPs idpinformers.WebhookIdentityProviderInformer, log logr.Logger) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "webhookcachecleaner-controller",
			Syncer: &controller{
				cache:       cache,
				webhookIDPs: webhookIDPs,
				log:         log.WithName("webhookcachecleaner-controller"),
			},
		},
		controllerlib.WithInformer(
			webhookIDPs,
			pinnipedcontroller.NoOpFilter(),
			controllerlib.InformerOption{},
		),
	)
}

type controller struct {
	cache       *idpcache.Cache
	webhookIDPs idpinformers.WebhookIdentityProviderInformer
	log         logr.Logger
}

// Sync implements controllerlib.Syncer.
func (c *controller) Sync(ctx controllerlib.Context) error {
	webhooks, err := c.webhookIDPs.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list WebhookIdentityProviders: %w", err)
	}

	// Index the current webhooks by key.
	webhooksByKey := map[controllerlib.Key]*idpv1alpha1.WebhookIdentityProvider{}
	for _, webhook := range webhooks {
		key := controllerlib.Key{Namespace: webhook.Namespace, Name: webhook.Name}
		webhooksByKey[key] = webhook
	}

	// Delete any entries from the cache which are no longer in the cluster.
	for _, key := range c.cache.Keys() {
		if _, exists := webhooksByKey[key]; !exists {
			c.log.WithValues("idp", klog.KRef(key.Namespace, key.Name)).Info("deleting webhook IDP from cache")
			c.cache.Delete(key)
		}
	}
	return nil
}
