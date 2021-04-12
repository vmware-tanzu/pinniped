// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatcher

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/upstreamldap"
)

const (
	ldapControllerName        = "ldap-upstream-observer"
	ldapBindAccountSecretType = corev1.SecretTypeBasicAuth
)

// UpstreamLDAPIdentityProviderICache is a thread safe cache that holds a list of validated upstream LDAP IDP configurations.
type UpstreamLDAPIdentityProviderICache interface {
	SetLDAPIdentityProviders([]provider.UpstreamLDAPIdentityProviderI)
}

type ldapWatcherController struct {
	cache                        UpstreamLDAPIdentityProviderICache
	ldapDialer                   upstreamldap.LDAPDialer
	client                       pinnipedclientset.Interface
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer
	secretInformer               corev1informers.SecretInformer
}

// NewLDAPUpstreamWatcherController instantiates a new controllerlib.Controller which will populate the provided UpstreamLDAPIdentityProviderICache.
func NewLDAPUpstreamWatcherController(
	idpCache UpstreamLDAPIdentityProviderICache,
	ldapDialer upstreamldap.LDAPDialer,
	client pinnipedclientset.Interface,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	c := ldapWatcherController{
		cache:                        idpCache,
		ldapDialer:                   ldapDialer,
		client:                       client,
		ldapIdentityProviderInformer: ldapIdentityProviderInformer,
		secretInformer:               secretInformer,
	}
	return controllerlib.New(
		controllerlib.Config{Name: ldapControllerName, Syncer: &c},
		withInformer(
			ldapIdentityProviderInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypeFilter(ldapBindAccountSecretType, pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *ldapWatcherController) Sync(ctx controllerlib.Context) error {
	actualUpstreams, err := c.ldapIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list LDAPIdentityProviders: %w", err)
	}

	requeue := false
	validatedUpstreams := make([]provider.UpstreamLDAPIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		valid := c.validateUpstream(upstream)
		if valid == nil {
			requeue = true
		} else {
			validatedUpstreams = append(validatedUpstreams, valid)
		}
	}
	c.cache.SetLDAPIdentityProviders(validatedUpstreams)
	if requeue {
		return controllerlib.ErrSyntheticRequeue
	}
	return nil
}

func (c *ldapWatcherController) validateUpstream(upstream *v1alpha1.LDAPIdentityProvider) provider.UpstreamLDAPIdentityProviderI {
	spec := upstream.Spec
	result := &upstreamldap.Provider{
		Name:     upstream.Name,
		Host:     spec.Host,
		CABundle: []byte(spec.TLS.CertificateAuthorityData),
		UserSearch: &upstreamldap.UserSearch{
			Base:              spec.UserSearch.Base,
			Filter:            spec.UserSearch.Filter,
			UsernameAttribute: spec.UserSearch.Attributes.Username,
			UIDAttribute:      spec.UserSearch.Attributes.UniqueID,
		},
		Dialer: c.ldapDialer,
	}
	_ = c.validateSecret(upstream, result)
	return result
}

func (c ldapWatcherController) validateSecret(upstream *v1alpha1.LDAPIdentityProvider, result *upstreamldap.Provider) *v1alpha1.Condition {
	secretName := upstream.Spec.Bind.SecretName

	secret, err := c.secretInformer.Lister().Secrets(upstream.Namespace).Get(secretName)
	if err != nil {
		// TODO
		return nil
	}

	if secret.Type != corev1.SecretTypeBasicAuth {
		// TODO
		return nil
	}

	result.BindUsername = string(secret.Data[corev1.BasicAuthUsernameKey])
	result.BindPassword = string(secret.Data[corev1.BasicAuthPasswordKey])
	if len(result.BindUsername) == 0 || len(result.BindPassword) == 0 {
		// TODO
		return nil
	}

	var cond *v1alpha1.Condition // satisfy linter
	return cond
}
