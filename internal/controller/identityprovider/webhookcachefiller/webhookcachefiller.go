// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachefiller implements a controller for filling an idpcache.Cache with each added/updated WebhookIdentityProvider.
package webhookcachefiller

import (
	"encoding/base64"
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

	idpv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/idp/v1alpha1"
	idpinformers "github.com/suzerain-io/pinniped/generated/1.19/client/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	"github.com/suzerain-io/pinniped/internal/controller/identityprovider/idpcache"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
)

// New instantiates a new controllerlib.Controller which will populate the provided idpcache.Cache.
func New(cache *idpcache.Cache, webhookIDPs idpinformers.WebhookIdentityProviderInformer, log logr.Logger) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "webhookcachefiller-controller",
			Syncer: &controller{
				cache:       cache,
				webhookIDPs: webhookIDPs,
				log:         log.WithName("webhookcachefiller-controller"),
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
	obj, err := c.webhookIDPs.Lister().WebhookIdentityProviders(ctx.Key.Namespace).Get(ctx.Key.Name)
	if err != nil && errors.IsNotFound(err) {
		c.log.Info("Sync() found that the WebhookIdentityProvider does not exist yet or was deleted")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get WebhookIdentityProvider %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	webhookAuthenticator, err := newWebhookAuthenticator(&obj.Spec, ioutil.TempFile, clientcmd.WriteToFile)
	if err != nil {
		return fmt.Errorf("failed to build webhook config: %w", err)
	}

	c.cache.Store(ctx.Key, webhookAuthenticator)
	c.log.WithValues("idp", klog.KObj(obj), "endpoint", obj.Spec.Endpoint).Info("added new webhook IDP")
	return nil
}

// newWebhookAuthenticator creates a webhook from the provided API server url and caBundle
// used to validate TLS connections.
func newWebhookAuthenticator(
	spec *idpv1alpha1.WebhookIdentityProviderSpec,
	tempfileFunc func(string, string) (*os.File, error),
	marshalFunc func(clientcmdapi.Config, string) error,
) (*webhook.WebhookTokenAuthenticator, error) {
	temp, err := tempfileFunc("", "pinniped-webhook-kubeconfig-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary file: %w", err)
	}
	defer func() { _ = os.Remove(temp.Name()) }()

	cluster := &clientcmdapi.Cluster{Server: spec.Endpoint}
	cluster.CertificateAuthorityData, err = getCABundle(spec.TLS)
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

	return webhook.New(temp.Name(), version, implicitAuds, customDial)
}

func getCABundle(spec *idpv1alpha1.TLSSpec) ([]byte, error) {
	if spec == nil {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(spec.CertificateAuthorityData)
}
