// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package ldapupstreamwatcher implements a controller which watches LDAPIdentityProviders.
package ldapupstreamwatcher

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

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
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/upstreamldap"
)

const (
	ldapControllerName        = "ldap-upstream-observer"
	ldapBindAccountSecretType = corev1.SecretTypeBasicAuth
	testLDAPConnectionTimeout = 90 * time.Second

	// Constants related to conditions.
	typeBindSecretValid           = "BindSecretValid"
	typeTLSConfigurationValid     = "TLSConfigurationValid"
	typeLDAPConnectionValid       = "LDAPConnectionValid"
	reasonLDAPConnectionError     = "LDAPConnectionError"
	noTLSConfigurationMessage     = "no TLS configuration provided"
	loadedTLSConfigurationMessage = "loaded TLS configuration"
)

var (
	secretVersionParser = regexp.MustCompile(` \[validated with Secret ".+" at version "(.+)"]`)
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

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamLDAPIdentityProviderICache.
func New(
	idpCache UpstreamLDAPIdentityProviderICache,
	client pinnipedclientset.Interface,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	// nil means to use a real production dialer when creating objects to add to the dynamicUpstreamIDPProvider cache.
	return newInternal(idpCache, nil, client, ldapIdentityProviderInformer, secretInformer, withInformer)
}

func newInternal(
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

	config := &upstreamldap.ProviderConfig{
		Name: upstream.Name,
		Host: spec.Host,
		UserSearch: upstreamldap.UserSearchConfig{
			Base:              spec.UserSearch.Base,
			Filter:            spec.UserSearch.Filter,
			UsernameAttribute: spec.UserSearch.Attributes.Username,
			UIDAttribute:      spec.UserSearch.Attributes.UID,
		},
		Dialer: c.ldapDialer,
	}

	conditions := []*v1alpha1.Condition{}
	secretValidCondition, currentSecretVersion := c.validateSecret(upstream, config)
	tlsValidCondition := c.validateTLSConfig(upstream, config)
	conditions = append(conditions, secretValidCondition, tlsValidCondition)

	// No point in trying to connect to the server if the config was already determined to be invalid.
	if secretValidCondition.Status == v1alpha1.ConditionTrue && tlsValidCondition.Status == v1alpha1.ConditionTrue {
		finishedConfigCondition := c.validateFinishedConfig(ctx, upstream, config, currentSecretVersion)
		// nil when there is no need to update this condition.
		if finishedConfigCondition != nil {
			conditions = append(conditions, finishedConfigCondition)
		}
	}

	hadErrorCondition := c.updateStatus(ctx, upstream, conditions)
	if hadErrorCondition {
		return nil
	}

	return upstreamldap.New(*config)
}

func (c *ldapWatcherController) validateTLSConfig(upstream *v1alpha1.LDAPIdentityProvider, config *upstreamldap.ProviderConfig) *v1alpha1.Condition {
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
		return c.invalidTLSCondition(fmt.Sprintf("certificateAuthorityData is invalid: %s", upstreamwatchers.ErrNoCertificates))
	}

	config.CABundle = bundle
	return c.validTLSCondition(loadedTLSConfigurationMessage)
}

func (c *ldapWatcherController) validateFinishedConfig(ctx context.Context, upstream *v1alpha1.LDAPIdentityProvider, config *upstreamldap.ProviderConfig, currentSecretVersion string) *v1alpha1.Condition {
	ldapProvider := upstreamldap.New(*config)

	if hasPreviousSuccessfulConditionForCurrentSpecGenerationAndSecretVersion(upstream, currentSecretVersion) {
		return nil
	}

	testConnectionTimeout, cancelFunc := context.WithTimeout(ctx, testLDAPConnectionTimeout)
	defer cancelFunc()

	return c.testConnection(testConnectionTimeout, upstream, config, ldapProvider, currentSecretVersion)
}

func (c *ldapWatcherController) testConnection(
	ctx context.Context,
	upstream *v1alpha1.LDAPIdentityProvider,
	config *upstreamldap.ProviderConfig,
	ldapProvider *upstreamldap.Provider,
	currentSecretVersion string,
) *v1alpha1.Condition {
	err := ldapProvider.TestConnection(ctx)
	if err != nil {
		return &v1alpha1.Condition{
			Type:   typeLDAPConnectionValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonLDAPConnectionError,
			Message: fmt.Sprintf(`could not successfully connect to "%s" and bind as user "%s": %s`,
				config.Host, config.BindUsername, err.Error()),
		}
	}

	return &v1alpha1.Condition{
		Type:   typeLDAPConnectionValid,
		Status: v1alpha1.ConditionTrue,
		Reason: upstreamwatchers.ReasonSuccess,
		Message: fmt.Sprintf(`successfully able to connect to "%s" and bind as user "%s" [validated with Secret "%s" at version "%s"]`,
			config.Host, config.BindUsername, upstream.Spec.Bind.SecretName, currentSecretVersion),
	}
}

func hasPreviousSuccessfulConditionForCurrentSpecGenerationAndSecretVersion(upstream *v1alpha1.LDAPIdentityProvider, currentSecretVersion string) bool {
	currentGeneration := upstream.Generation
	for _, c := range upstream.Status.Conditions {
		if c.Type == typeLDAPConnectionValid && c.Status == v1alpha1.ConditionTrue && c.ObservedGeneration == currentGeneration {
			// Found a previously successful condition for the current spec generation.
			// Now figure out which version of the bind Secret was used during that previous validation.
			matches := secretVersionParser.FindStringSubmatch(c.Message)
			if len(matches) != 2 {
				continue
			}
			validatedSecretVersion := matches[1]
			if validatedSecretVersion == currentSecretVersion {
				return true
			}
		}
	}
	return false
}

func (c *ldapWatcherController) validTLSCondition(message string) *v1alpha1.Condition {
	return &v1alpha1.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  v1alpha1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: message,
	}
}

func (c *ldapWatcherController) invalidTLSCondition(message string) *v1alpha1.Condition {
	return &v1alpha1.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  v1alpha1.ConditionFalse,
		Reason:  upstreamwatchers.ReasonInvalidTLSConfig,
		Message: message,
	}
}

func (c *ldapWatcherController) validateSecret(upstream *v1alpha1.LDAPIdentityProvider, config *upstreamldap.ProviderConfig) (*v1alpha1.Condition, string) {
	secretName := upstream.Spec.Bind.SecretName

	secret, err := c.secretInformer.Lister().Secrets(upstream.Namespace).Get(secretName)
	if err != nil {
		return &v1alpha1.Condition{
			Type:    typeBindSecretValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  upstreamwatchers.ReasonNotFound,
			Message: err.Error(),
		}, ""
	}

	if secret.Type != corev1.SecretTypeBasicAuth {
		return &v1alpha1.Condition{
			Type:   typeBindSecretValid,
			Status: v1alpha1.ConditionFalse,
			Reason: upstreamwatchers.ReasonWrongType,
			Message: fmt.Sprintf("referenced Secret %q has wrong type %q (should be %q)",
				secretName, secret.Type, corev1.SecretTypeBasicAuth),
		}, secret.ResourceVersion
	}

	config.BindUsername = string(secret.Data[corev1.BasicAuthUsernameKey])
	config.BindPassword = string(secret.Data[corev1.BasicAuthPasswordKey])
	if len(config.BindUsername) == 0 || len(config.BindPassword) == 0 {
		return &v1alpha1.Condition{
			Type:   typeBindSecretValid,
			Status: v1alpha1.ConditionFalse,
			Reason: upstreamwatchers.ReasonMissingKeys,
			Message: fmt.Sprintf("referenced Secret %q is missing required keys %q",
				secretName, []string{corev1.BasicAuthUsernameKey, corev1.BasicAuthPasswordKey}),
		}, secret.ResourceVersion
	}

	return &v1alpha1.Condition{
		Type:    typeBindSecretValid,
		Status:  v1alpha1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: "loaded bind secret",
	}, secret.ResourceVersion
}

func (c *ldapWatcherController) updateStatus(ctx context.Context, upstream *v1alpha1.LDAPIdentityProvider, conditions []*v1alpha1.Condition) bool {
	log := klogr.New().WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.Merge(conditions, upstream.Generation, &updated.Status.Conditions, log)

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
