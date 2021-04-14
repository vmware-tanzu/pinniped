// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatcher

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2/klogr"

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

	// Constants related to conditions.
	typeBindSecretValid           = "BindSecretValid"
	tlsConfigurationValid         = "TLSConfigurationValid"
	noTLSConfigurationMessage     = "no TLS configuration provided"
	loadedTLSConfigurationMessage = "loaded TLS configuration"
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
		valid := c.validateUpstream(ctx.Context, upstream)
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

func (c *ldapWatcherController) validateUpstream(ctx context.Context, upstream *v1alpha1.LDAPIdentityProvider) provider.UpstreamLDAPIdentityProviderI {
	spec := upstream.Spec

	result := &upstreamldap.Provider{
		Name: upstream.Name,
		Host: spec.Host,
		UserSearch: &upstreamldap.UserSearch{
			Base:              spec.UserSearch.Base,
			Filter:            spec.UserSearch.Filter,
			UsernameAttribute: spec.UserSearch.Attributes.Username,
			UIDAttribute:      spec.UserSearch.Attributes.UniqueID,
		},
		Dialer: c.ldapDialer,
	}
	conditions := []*v1alpha1.Condition{
		c.validateSecret(upstream, result),
		c.validateTLSConfig(upstream, result),
	}
	hadErrorCondition := c.updateStatus(ctx, upstream, conditions)
	if hadErrorCondition {
		return nil
	}
	return result
}

func (c *ldapWatcherController) validateTLSConfig(upstream *v1alpha1.LDAPIdentityProvider, result *upstreamldap.Provider) *v1alpha1.Condition {
	tlsSpec := upstream.Spec.TLS
	if tlsSpec == nil {
		return c.validTLSCondition(noTLSConfigurationMessage)
	}
	if len(tlsSpec.CertificateAuthorityData) == 0 {
		return c.validTLSCondition(loadedTLSConfigurationMessage)
	}

	bundle, err := base64.StdEncoding.DecodeString(tlsSpec.CertificateAuthorityData)
	if err != nil {
		return c.invalidTLSCondition(fmt.Sprintf("certificateAuthorityData is invalid: %s", err.Error()))
	}

	ca := x509.NewCertPool()
	ok := ca.AppendCertsFromPEM(bundle)
	if !ok {
		return c.invalidTLSCondition(fmt.Sprintf("certificateAuthorityData is invalid: %s", errNoCertificates))
	}

	result.CABundle = bundle
	return c.validTLSCondition(loadedTLSConfigurationMessage)
}

func (c *ldapWatcherController) validTLSCondition(message string) *v1alpha1.Condition {
	return &v1alpha1.Condition{
		Type:    tlsConfigurationValid,
		Status:  v1alpha1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: message,
	}
}

func (c *ldapWatcherController) invalidTLSCondition(message string) *v1alpha1.Condition {
	return &v1alpha1.Condition{
		Type:    tlsConfigurationValid,
		Status:  v1alpha1.ConditionFalse,
		Reason:  reasonInvalidTLSConfig,
		Message: message,
	}
}

func (c *ldapWatcherController) validateSecret(upstream *v1alpha1.LDAPIdentityProvider, result *upstreamldap.Provider) *v1alpha1.Condition {
	secretName := upstream.Spec.Bind.SecretName

	secret, err := c.secretInformer.Lister().Secrets(upstream.Namespace).Get(secretName)
	if err != nil {
		return &v1alpha1.Condition{
			Type:    typeBindSecretValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonNotFound,
			Message: err.Error(),
		}
	}

	if secret.Type != corev1.SecretTypeBasicAuth {
		return &v1alpha1.Condition{
			Type:    typeBindSecretValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonWrongType,
			Message: fmt.Sprintf("referenced Secret %q has wrong type %q (should be %q)", secretName, secret.Type, corev1.SecretTypeBasicAuth),
		}
	}

	result.BindUsername = string(secret.Data[corev1.BasicAuthUsernameKey])
	result.BindPassword = string(secret.Data[corev1.BasicAuthPasswordKey])
	if len(result.BindUsername) == 0 || len(result.BindPassword) == 0 {
		return &v1alpha1.Condition{
			Type:    typeBindSecretValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonMissingKeys,
			Message: fmt.Sprintf("referenced Secret %q is missing required keys %q", secretName, []string{corev1.BasicAuthUsernameKey, corev1.BasicAuthPasswordKey}),
		}
	}

	return &v1alpha1.Condition{
		Type:    typeBindSecretValid,
		Status:  v1alpha1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: "loaded bind secret",
	}
}

func (c *ldapWatcherController) updateStatus(ctx context.Context, upstream *v1alpha1.LDAPIdentityProvider, conditions []*v1alpha1.Condition) bool {
	log := klogr.New().WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := mergeConditions(conditions, upstream.Generation, &updated.Status.Conditions, log)

	updated.Status.Phase = v1alpha1.LDAPPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = v1alpha1.LDAPPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return hadErrorCondition
	}

	_, err := c.client.
		IDPV1alpha1().
		LDAPIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		log.Error(err, "failed to update status")
	}

	return hadErrorCondition
}
