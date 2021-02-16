// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachefiller implements a controller for filling an authncache.Cache with each added/updated WebhookAuthenticator.
package webhookcachefiller

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-logr/logr"
	k8sauthv1beta1 "k8s.io/api/authentication/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	pinnipedauthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
)

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(cache *authncache.Cache, webhooks authinformers.WebhookAuthenticatorInformer, log logr.Logger) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "webhookcachefiller-controller",
			Syncer: &controller{
				cache:    cache,
				webhooks: webhooks,
				log:      log.WithName("webhookcachefiller-controller"),
			},
		},
		controllerlib.WithInformer(
			webhooks,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
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
func (c *controller) Sync(ctx controllerlib.Context) error {
	obj, err := c.webhooks.Lister().Get(ctx.Key.Name)
	if err != nil && errors.IsNotFound(err) {
		c.log.Info("Sync() found that the WebhookAuthenticator does not exist yet or was deleted")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get WebhookAuthenticator %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	webhookAuthenticator, err := newWebhookAuthenticator(&obj.Spec, ioutil.TempFile, clientcmd.WriteToFile)
	if err != nil {
		return fmt.Errorf("failed to build webhook config: %w", err)
	}

	c.cache.Store(authncache.Key{
		APIGroup: auth1alpha1.GroupName,
		Kind:     "WebhookAuthenticator",
		Name:     ctx.Key.Name,
	}, webhookAuthenticator)
	c.log.WithValues("webhook", klog.KObj(obj), "endpoint", obj.Spec.Endpoint).Info("added new webhook authenticator")
	return nil
}

// newWebhookAuthenticator creates a webhook from the provided API server url and caBundle
// used to validate TLS connections.
func newWebhookAuthenticator(
	spec *auth1alpha1.WebhookAuthenticatorSpec,
	tempfileFunc func(string, string) (*os.File, error),
	marshalFunc func(clientcmdapi.Config, string) error,
) (*webhook.WebhookTokenAuthenticator, error) {
	temp, err := tempfileFunc("", "pinniped-webhook-kubeconfig-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary file: %w", err)
	}
	defer func() { _ = os.Remove(temp.Name()) }()

	cluster := &clientcmdapi.Cluster{Server: spec.Endpoint}
	cluster.CertificateAuthorityData, err = pinnipedauthenticator.CABundle(spec.TLS)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	kubeconfig := clientcmdapi.NewConfig()
	kubeconfig.Clusters["anonymous-cluster"] = cluster
	kubeconfig.Contexts["anonymous"] = &clientcmdapi.Context{Cluster: "anonymous-cluster"}
	kubeconfig.CurrentContext = "anonymous"

	if err := marshalFunc(*kubeconfig, temp.Name()); err != nil {
		return nil, fmt.Errorf("unable to marshal kubeconfig: %w", err)
	}

	// We use v1beta1 instead of v1 since v1beta1 is more prevalent in our desired
	// integration points.
	version := k8sauthv1beta1.SchemeGroupVersion.Version

	// At the current time, we don't provide any audiences because we simply don't
	// have any requirements to do so. This can be changed in the future as
	// requirements change.
	var implicitAuds authenticator.Audiences

	// We set this to nil because we would only need this to support some of the
	// custom proxy stuff used by the API server.
	var customDial net.DialFunc

	return webhook.New(temp.Name(), version, implicitAuds, *webhook.DefaultRetryBackoff(), customDial)
}
