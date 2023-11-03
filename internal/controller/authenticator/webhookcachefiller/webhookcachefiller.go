// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachefiller implements a controller for filling an authncache.Cache with each added/updated WebhookAuthenticator.
package webhookcachefiller

import (
	"context"
	"fmt"
	"os"

	k8sauthv1beta1 "k8s.io/api/authentication/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	webhookutil "k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	pinnipedauthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

func (c *config) updateWebhookAuthStatus(ctx context.Context, upstream *auth1alpha1.WebhookAuthenticator, conditions []*metav1.Condition) {
	var client conciergeclientset.Interface

	toUpdate := upstream.DeepCopy()

	_ = conditionsutil.MergeIDPConditions(conditions, upstream.Generation, &toUpdate.Status.Conditions, c.logger)

	_, err := client.AuthenticationV1alpha1().WebhookAuthenticators().UpdateStatus(ctx, toUpdate, metav1.UpdateOptions{})
	if err != nil {
		c.logger.Error(fmt.Sprintf("unable to update %s with name %s", toUpdate.TypeMeta.Kind, toUpdate.ObjectMeta.Name), err)
	}
}

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(
	cache *authncache.Cache,
	webhooks authinformers.WebhookAuthenticatorInformer,
	logger plog.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "webhookcachefiller-controller",
			Syncer: &config{
				cache:    cache,
				webhooks: webhooks,
				logger:   logger.WithName("webhookcachefiller-controller"),
			},
		},
		controllerlib.WithInformer(
			webhooks,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

type config struct {
	cache    *authncache.Cache
	webhooks authinformers.WebhookAuthenticatorInformer
	logger   plog.Logger
}

func buildCondition(err error) []*metav1.Condition {
	if err == nil {
		return []*metav1.Condition{
			{
				Type:   "Ready",
				Status: metav1.ConditionTrue,
				Reason: upstreamwatchers.ReasonSuccess,
			},
		}
	}

	return []*metav1.Condition{
		{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: err.Error(),
		},
	}
}

func (c *config) Sync(ctx controllerlib.Context) (err error) {
	webhookAuthenticator, err := c.webhooks.Lister().Get(ctx.Key.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			c.logger.Info("Sync() found that the WebhookAuthenticator does not exist yet or was deleted")
			return nil
		}
		c.updateWebhookAuthStatus(ctx.Context, webhookAuthenticator, buildCondition(err))
		return fmt.Errorf("failed to get WebhookAuthenticator %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	webhookTokenAuthenticator, err := newWebhookTokenAuthenticator(&webhookAuthenticator.Spec, os.CreateTemp, clientcmd.WriteToFile)
	if err != nil {
		c.updateWebhookAuthStatus(ctx.Context, webhookAuthenticator, buildCondition(err))
		return fmt.Errorf("failed to build webhook config: %w", err)
	}

	c.cache.Store(authncache.Key{
		APIGroup: auth1alpha1.GroupName,
		Kind:     webhookAuthenticator.Kind,
		Name:     ctx.Key.Name,
	}, webhookTokenAuthenticator)
	c.logger.WithValues("webhook", klog.KObj(webhookAuthenticator), "endpoint", webhookAuthenticator.Spec.Endpoint).Info("added new webhook authenticator")
	c.updateWebhookAuthStatus(ctx.Context, webhookAuthenticator, buildCondition(err))
	return nil
}

// newWebhookTokenAuthenticator creates a webhook from the provided API server url and caBundle
// used to validate TLS connections.
func newWebhookTokenAuthenticator(
	spec *auth1alpha1.WebhookAuthenticatorSpec,
	tempfileFunc func(string, string) (*os.File, error),
	marshalFunc func(clientcmdapi.Config, string) error,
) (*webhook.WebhookTokenAuthenticator, error) {
	tempFile, err := tempfileFunc("", "pinniped-webhook-kubeconfig-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tempFile.Name()) }()

	cluster := &clientcmdapi.Cluster{Server: spec.Endpoint}
	_, cluster.CertificateAuthorityData, err = pinnipedauthenticator.CABundle(spec.TLS)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	kubeconfig := clientcmdapi.NewConfig()
	kubeconfig.Clusters["anonymous-cluster"] = cluster
	kubeconfig.Contexts["anonymous"] = &clientcmdapi.Context{Cluster: "anonymous-cluster"}
	kubeconfig.CurrentContext = "anonymous"

	if err := marshalFunc(*kubeconfig, tempFile.Name()); err != nil {
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

	// TODO refactor this code to directly construct the rest.Config
	//  ideally we would keep rest config generation contained to the kubeclient package
	//  but this will require some form of a new WithTLSConfigFunc kubeclient.Option
	//  ex:
	//  _, caBundle, err := pinnipedauthenticator.CABundle(spec.TLS)
	//  ...
	//  restConfig := &rest.Config{
	//    Host:            spec.Endpoint,
	//    TLSClientConfig: rest.TLSClientConfig{CAData: caBundle},
	//    // copied from k8s.io/apiserver/pkg/util/webhook
	//    Timeout: 30 * time.Second,
	//    QPS:     -1,
	//  }
	//  client, err := kubeclient.New(kubeclient.WithConfig(restConfig), kubeclient.WithTLSConfigFunc(ptls.Default))
	//  ...
	//  then use client.JSONConfig as clientConfig
	clientConfig, err := webhookutil.LoadKubeconfig(tempFile.Name(), customDial)
	if err != nil {
		return nil, err
	}

	// this uses a http client that does not honor our TLS config
	// TODO fix when we pick up https://github.com/kubernetes/kubernetes/pull/106155
	return webhook.New(clientConfig, version, implicitAuds, *webhook.DefaultRetryBackoff())
}
