// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	"go.pinniped.dev/generated/1.19/client/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type tlsCertObserverController struct {
	issuerHostToTLSCertMapSetter IssuerHostToTLSCertMapSetter
	oidcProviderConfigInformer   v1alpha1.OIDCProviderConfigInformer
	secretInformer               corev1informers.SecretInformer
}

type IssuerHostToTLSCertMapSetter interface {
	SetIssuerHostToTLSCertMap(issuerHostToTLSCertMap map[string]*tls.Certificate)
}

func NewTLSCertObserverController(
	issuerHostToTLSCertMapSetter IssuerHostToTLSCertMapSetter,
	secretInformer corev1informers.SecretInformer,
	oidcProviderConfigInformer v1alpha1.OIDCProviderConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "tls-certs-observer-controller",
			Syncer: &tlsCertObserverController{
				issuerHostToTLSCertMapSetter: issuerHostToTLSCertMapSetter,
				oidcProviderConfigInformer:   oidcProviderConfigInformer,
				secretInformer:               secretInformer,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnythingFilter(),
			controllerlib.InformerOption{},
		),
		withInformer(
			oidcProviderConfigInformer,
			pinnipedcontroller.MatchAnythingFilter(),
			controllerlib.InformerOption{},
		),
	)
}

func (c *tlsCertObserverController) Sync(ctx controllerlib.Context) error {
	ns := ctx.Key.Namespace
	allProviders, err := c.oidcProviderConfigInformer.Lister().OIDCProviderConfigs(ns).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list OIDCProviderConfigs: %w", err)
	}

	// Rebuild the whole map on any change to any Secret or OIDCProvider, because either can have changes that
	// can cause the map to need to be updated.
	issuerHostToTLSCertMap := map[string]*tls.Certificate{}

	for _, provider := range allProviders {
		secretName := provider.Spec.SNICertificateSecretName
		issuerURL, err := url.Parse(provider.Spec.Issuer)
		if err != nil {
			klog.InfoS("tlsCertObserverController Sync found an invalid issuer URL", "namespace", ns, "issuer", provider.Spec.Issuer)
			continue
		}
		tlsSecret, err := c.secretInformer.Lister().Secrets(ns).Get(secretName)
		if err != nil {
			klog.InfoS("tlsCertObserverController Sync could not find TLS cert secret", "namespace", ns, "secretName", secretName)
			continue
		}
		certFromSecret, err := tls.X509KeyPair(tlsSecret.Data["tls.crt"], tlsSecret.Data["tls.key"])
		if err != nil {
			klog.InfoS("tlsCertObserverController Sync found a TLS secret with Data in an unexpected format", "namespace", ns, "secretName", secretName)
			continue
		}
		// Lowercase the host part of the URL because hostnames should be treated as case-insensitive.
		issuerHostToTLSCertMap[lowercaseHostWithoutPort(issuerURL)] = &certFromSecret
	}

	klog.InfoS("tlsCertObserverController Sync updated the TLS cert cache", "issuerHostCount", len(issuerHostToTLSCertMap))
	c.issuerHostToTLSCertMapSetter.SetIssuerHostToTLSCertMap(issuerHostToTLSCertMap)

	return nil
}

func lowercaseHostWithoutPort(issuerURL *url.URL) string {
	lowercaseHost := strings.ToLower(issuerURL.Host)
	colonSegments := strings.Split(lowercaseHost, ":")
	return colonSegments[0]
}
