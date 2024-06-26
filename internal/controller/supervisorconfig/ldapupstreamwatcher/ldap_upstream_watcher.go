// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package ldapupstreamwatcher implements a controller which watches LDAPIdentityProviders.
package ldapupstreamwatcher

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamldap"
)

const (
	ldapControllerName = "ldap-upstream-observer"
)

type ldapUpstreamGenericLDAPImpl struct {
	ldapIdentityProvider idpv1alpha1.LDAPIdentityProvider
}

func (g *ldapUpstreamGenericLDAPImpl) Spec() upstreamwatchers.UpstreamGenericLDAPSpec {
	return &ldapUpstreamGenericLDAPSpec{g.ldapIdentityProvider}
}

func (g *ldapUpstreamGenericLDAPImpl) Namespace() string {
	return g.ldapIdentityProvider.Namespace
}

func (g *ldapUpstreamGenericLDAPImpl) Name() string {
	return g.ldapIdentityProvider.Name
}

func (g *ldapUpstreamGenericLDAPImpl) Generation() int64 {
	return g.ldapIdentityProvider.Generation
}

func (g *ldapUpstreamGenericLDAPImpl) Status() upstreamwatchers.UpstreamGenericLDAPStatus {
	return &ldapUpstreamGenericLDAPStatus{g.ldapIdentityProvider}
}

type ldapUpstreamGenericLDAPSpec struct {
	ldapIdentityProvider idpv1alpha1.LDAPIdentityProvider
}

func (s *ldapUpstreamGenericLDAPSpec) Host() string {
	return s.ldapIdentityProvider.Spec.Host
}

func (s *ldapUpstreamGenericLDAPSpec) TLSSpec() *idpv1alpha1.TLSSpec {
	return s.ldapIdentityProvider.Spec.TLS
}

func (s *ldapUpstreamGenericLDAPSpec) BindSecretName() string {
	return s.ldapIdentityProvider.Spec.Bind.SecretName
}

func (s *ldapUpstreamGenericLDAPSpec) UserSearch() upstreamwatchers.UpstreamGenericLDAPUserSearch {
	return &ldapUpstreamGenericLDAPUserSearch{s.ldapIdentityProvider.Spec.UserSearch}
}

func (s *ldapUpstreamGenericLDAPSpec) GroupSearch() upstreamwatchers.UpstreamGenericLDAPGroupSearch {
	return &ldapUpstreamGenericLDAPGroupSearch{s.ldapIdentityProvider.Spec.GroupSearch}
}

func (s *ldapUpstreamGenericLDAPSpec) DetectAndSetSearchBase(_ context.Context, config *upstreamldap.ProviderConfig) *metav1.Condition {
	config.GroupSearch.Base = s.ldapIdentityProvider.Spec.GroupSearch.Base
	config.UserSearch.Base = s.ldapIdentityProvider.Spec.UserSearch.Base
	return nil
}

type ldapUpstreamGenericLDAPUserSearch struct {
	userSearch idpv1alpha1.LDAPIdentityProviderUserSearch
}

func (u *ldapUpstreamGenericLDAPUserSearch) Base() string {
	return u.userSearch.Base
}

func (u *ldapUpstreamGenericLDAPUserSearch) Filter() string {
	return u.userSearch.Filter
}

func (u *ldapUpstreamGenericLDAPUserSearch) UsernameAttribute() string {
	return u.userSearch.Attributes.Username
}

func (u *ldapUpstreamGenericLDAPUserSearch) UIDAttribute() string {
	return u.userSearch.Attributes.UID
}

type ldapUpstreamGenericLDAPGroupSearch struct {
	groupSearch idpv1alpha1.LDAPIdentityProviderGroupSearch
}

func (g *ldapUpstreamGenericLDAPGroupSearch) Base() string {
	return g.groupSearch.Base
}

func (g *ldapUpstreamGenericLDAPGroupSearch) Filter() string {
	return g.groupSearch.Filter
}

func (g *ldapUpstreamGenericLDAPGroupSearch) UserAttributeForFilter() string {
	return g.groupSearch.UserAttributeForFilter
}

func (g *ldapUpstreamGenericLDAPGroupSearch) GroupNameAttribute() string {
	return g.groupSearch.Attributes.GroupName
}

type ldapUpstreamGenericLDAPStatus struct {
	ldapIdentityProvider idpv1alpha1.LDAPIdentityProvider
}

func (s *ldapUpstreamGenericLDAPStatus) Conditions() []metav1.Condition {
	return s.ldapIdentityProvider.Status.Conditions
}

// UpstreamLDAPIdentityProviderICache is a thread safe cache that holds a list of validated upstream LDAP IDP configurations.
type UpstreamLDAPIdentityProviderICache interface {
	SetLDAPIdentityProviders([]upstreamprovider.UpstreamLDAPIdentityProviderI)
}

type ldapWatcherController struct {
	cache                        UpstreamLDAPIdentityProviderICache
	validatedSettingsCache       upstreamwatchers.ValidatedSettingsCacheI
	ldapDialer                   upstreamldap.LDAPDialer
	client                       supervisorclientset.Interface
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer
	secretInformer               corev1informers.SecretInformer
	configMapInformer            corev1informers.ConfigMapInformer
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamLDAPIdentityProviderICache.
func New(
	idpCache UpstreamLDAPIdentityProviderICache,
	client supervisorclientset.Interface,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return newInternal(
		idpCache,
		// start with an empty cache
		upstreamwatchers.NewValidatedSettingsCache(),
		// nil means to use a real production dialer when creating objects to add to the cache
		nil,
		client,
		ldapIdentityProviderInformer,
		secretInformer,
		withInformer,
	)
}

// For test dependency injection purposes.
func newInternal(
	idpCache UpstreamLDAPIdentityProviderICache,
	validatedSettingsCache upstreamwatchers.ValidatedSettingsCacheI,
	ldapDialer upstreamldap.LDAPDialer,
	client supervisorclientset.Interface,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	c := ldapWatcherController{
		cache:                        idpCache,
		validatedSettingsCache:       validatedSettingsCache,
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
			pinnipedcontroller.MatchAnySecretOfTypeFilter(upstreamwatchers.LDAPBindAccountSecretType, pinnipedcontroller.SingletonQueue()),
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
	validatedUpstreams := make([]upstreamprovider.UpstreamLDAPIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		validProvider, requestedRequeue := c.validateUpstream(ctx.Context, upstream)
		if validProvider != nil {
			validatedUpstreams = append(validatedUpstreams, validProvider)
		}
		if requestedRequeue {
			requeue = true
		}
	}

	c.cache.SetLDAPIdentityProviders(validatedUpstreams)

	if requeue {
		return controllerlib.ErrSyntheticRequeue
	}
	return nil
}

func (c *ldapWatcherController) validateUpstream(ctx context.Context, upstream *idpv1alpha1.LDAPIdentityProvider) (p upstreamprovider.UpstreamLDAPIdentityProviderI, requeue bool) {
	spec := upstream.Spec

	config := &upstreamldap.ProviderConfig{
		Name:        upstream.Name,
		ResourceUID: upstream.UID,
		Host:        spec.Host,
		UserSearch: upstreamldap.UserSearchConfig{
			Base:              spec.UserSearch.Base,
			Filter:            spec.UserSearch.Filter,
			UsernameAttribute: spec.UserSearch.Attributes.Username,
			UIDAttribute:      spec.UserSearch.Attributes.UID,
		},
		GroupSearch: upstreamldap.GroupSearchConfig{
			Base:                   spec.GroupSearch.Base,
			Filter:                 spec.GroupSearch.Filter,
			UserAttributeForFilter: spec.GroupSearch.UserAttributeForFilter,
			GroupNameAttribute:     spec.GroupSearch.Attributes.GroupName,
			SkipGroupRefresh:       spec.GroupSearch.SkipGroupRefresh,
		},
		Dialer: c.ldapDialer,
	}

	conditions := upstreamwatchers.ValidateGenericLDAP(ctx, &ldapUpstreamGenericLDAPImpl{*upstream}, c.secretInformer, c.configMapInformer, c.validatedSettingsCache, config)

	c.updateStatus(ctx, upstream, conditions.Conditions())

	return upstreamwatchers.EvaluateConditions(conditions, config)
}

func (c *ldapWatcherController) updateStatus(ctx context.Context, upstream *idpv1alpha1.LDAPIdentityProvider, conditions []*metav1.Condition) {
	log := plog.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(conditions, upstream.Generation, &updated.Status.Conditions, log, metav1.Now())

	updated.Status.Phase = idpv1alpha1.LDAPPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = idpv1alpha1.LDAPPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return // nothing to update
	}

	_, err := c.client.
		IDPV1alpha1().
		LDAPIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		log.Error("failed to update status", err)
	}
}
