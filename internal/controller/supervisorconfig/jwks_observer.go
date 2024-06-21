// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

type jwksObserverController struct {
	issuerToJWKSSetter       IssuerToJWKSMapSetter
	federationDomainInformer v1alpha1.FederationDomainInformer
	secretInformer           corev1informers.SecretInformer
}

type IssuerToJWKSMapSetter interface {
	SetIssuerToJWKSMap(
		issuerToJWKSMap map[string]*jose.JSONWebKeySet,
		issuerToActiveJWKMap map[string]*jose.JSONWebKey,
	)
}

// Returns a controller which watches all of the FederationDomains and their corresponding Secrets
// and fills an in-memory cache of the JWKS info for each currently configured issuer.
// This controller assumes that the informers passed to it are already scoped down to the
// appropriate namespace. It also assumes that the IssuerToJWKSMapSetter passed to it has an
// underlying implementation which is thread-safe.
func NewJWKSObserverController(
	issuerToJWKSSetter IssuerToJWKSMapSetter,
	secretInformer corev1informers.SecretInformer,
	federationDomainInformer v1alpha1.FederationDomainInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "jwks-observer-controller",
			Syncer: &jwksObserverController{
				issuerToJWKSSetter:       issuerToJWKSSetter,
				federationDomainInformer: federationDomainInformer,
				secretInformer:           secretInformer,
			},
		},
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypeFilter(jwksSecretTypeValue, nil),
			controllerlib.InformerOption{},
		),
		withInformer(
			federationDomainInformer,
			pinnipedcontroller.MatchAnythingFilter(nil),
			controllerlib.InformerOption{},
		),
	)
}

func (c *jwksObserverController) Sync(ctx controllerlib.Context) error {
	ns := ctx.Key.Namespace
	allProviders, err := c.federationDomainInformer.Lister().FederationDomains(ns).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list FederationDomains: %w", err)
	}

	// Rebuild the whole map on any change to any Secret or FederationDomain, because either can have changes that
	// can cause the map to need to be updated.
	issuerToJWKSMap := map[string]*jose.JSONWebKeySet{}
	issuerToActiveJWKMap := map[string]*jose.JSONWebKey{}

	for _, provider := range allProviders {
		secretRef := provider.Status.Secrets.JWKS
		jwksSecret, err := c.secretInformer.Lister().Secrets(ns).Get(secretRef.Name)
		if err != nil {
			plog.Debug("jwksObserverController Sync could not find JWKS secret", "namespace", ns, "secretName", secretRef.Name)
			continue
		}

		jwksFromSecret := jose.JSONWebKeySet{}
		err = json.Unmarshal(jwksSecret.Data[jwksKey], &jwksFromSecret)
		if err != nil {
			plog.Debug("jwksObserverController Sync found a JWKS secret with Data in an unexpected format", "namespace", ns, "secretName", secretRef.Name)
			continue
		}

		activeJWKFromSecret := jose.JSONWebKey{}
		err = json.Unmarshal(jwksSecret.Data[activeJWKKey], &activeJWKFromSecret)
		if err != nil {
			plog.Debug("jwksObserverController Sync found an active JWK secret with Data in an unexpected format", "namespace", ns, "secretName", secretRef.Name)
			continue
		}

		issuerToJWKSMap[provider.Spec.Issuer] = &jwksFromSecret
		issuerToActiveJWKMap[provider.Spec.Issuer] = &activeJWKFromSecret
	}

	plog.Debug(
		"jwksObserverController Sync updated the JWKS cache",
		"issuerJWKSCount",
		len(issuerToJWKSMap),
		"issuerActiveJWKCount",
		len(issuerToActiveJWKMap),
	)
	c.issuerToJWKSSetter.SetIssuerToJWKSMap(issuerToJWKSMap, issuerToActiveJWKMap)

	return nil
}
