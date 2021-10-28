// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package activedirectoryupstreamwatcher implements a controller which watches ActiveDirectoryIdentityProviders.
package activedirectoryupstreamwatcher

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

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
	activeDirectoryControllerName = "active-directory-upstream-observer"

	// Default values for active directory config.
	defaultActiveDirectoryUsernameAttributeName = "userPrincipalName"
	defaultActiveDirectoryUIDAttributeName      = "objectGUID"

	// By default this group name attribute is the sAMAccountName with special mapping.
	// Each group will look like sAMAccountName + "@" + domain.
	// For example if your group sAMAccountName is "mammals" and your domain is
	// "activedirectory.example.com", it would be mammals@activedirectory.example.com.
	// This is because sAMAccountName is only unique within a domain, not a forest.
	defaultActiveDirectoryGroupNameAttributeName = "sAMAccountName"

	// - is a person.
	// - is not a computer.
	// - is not shown in advanced view only (which would likely mean its a system created service account with advanced permissions).
	// - either the sAMAccountName, the userPrincipalName or the mail attribute matches the input username.
	// - the sAMAccountType is for a normal user account.
	defaultActiveDirectoryUserSearchFilter = "(&(objectClass=person)(!(objectClass=computer))(!(showInAdvancedViewOnly=TRUE))(|(sAMAccountName={})(mail={})(userPrincipalName={}))(sAMAccountType=805306368))"

	// - is a group.
	// - has a member that matches the DN of the user we successfully logged in as.
	// - perform nested group search by default.
	defaultActiveDirectoryGroupSearchFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={}))"
)

type activeDirectoryUpstreamGenericLDAPImpl struct {
	activeDirectoryIdentityProvider v1alpha1.ActiveDirectoryIdentityProvider
}

func (g *activeDirectoryUpstreamGenericLDAPImpl) Spec() upstreamwatchers.UpstreamGenericLDAPSpec {
	return &activeDirectoryUpstreamGenericLDAPSpec{g.activeDirectoryIdentityProvider}
}

func (g *activeDirectoryUpstreamGenericLDAPImpl) Namespace() string {
	return g.activeDirectoryIdentityProvider.Namespace
}

func (g *activeDirectoryUpstreamGenericLDAPImpl) Name() string {
	return g.activeDirectoryIdentityProvider.Name
}

func (g *activeDirectoryUpstreamGenericLDAPImpl) Generation() int64 {
	return g.activeDirectoryIdentityProvider.Generation
}

func (g *activeDirectoryUpstreamGenericLDAPImpl) Status() upstreamwatchers.UpstreamGenericLDAPStatus {
	return &activeDirectoryUpstreamGenericLDAPStatus{g.activeDirectoryIdentityProvider}
}

type activeDirectoryUpstreamGenericLDAPSpec struct {
	activeDirectoryIdentityProvider v1alpha1.ActiveDirectoryIdentityProvider
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) Host() string {
	return s.activeDirectoryIdentityProvider.Spec.Host
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) TLSSpec() *v1alpha1.TLSSpec {
	return s.activeDirectoryIdentityProvider.Spec.TLS
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) BindSecretName() string {
	return s.activeDirectoryIdentityProvider.Spec.Bind.SecretName
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) UserSearch() upstreamwatchers.UpstreamGenericLDAPUserSearch {
	return &activeDirectoryUpstreamGenericLDAPUserSearch{s.activeDirectoryIdentityProvider.Spec.UserSearch}
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) GroupSearch() upstreamwatchers.UpstreamGenericLDAPGroupSearch {
	return &activeDirectoryUpstreamGenericLDAPGroupSearch{s.activeDirectoryIdentityProvider.Spec.GroupSearch}
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) DetectAndSetSearchBase(ctx context.Context, config *upstreamldap.ProviderConfig) *v1alpha1.Condition {
	config.GroupSearch.Base = s.activeDirectoryIdentityProvider.Spec.GroupSearch.Base
	config.UserSearch.Base = s.activeDirectoryIdentityProvider.Spec.UserSearch.Base
	if config.GroupSearch.Base != "" && config.UserSearch.Base != "" {
		// Both were already set in spec so just return; no need to query the RootDSE
		return &v1alpha1.Condition{
			Type:    upstreamwatchers.TypeSearchBaseFound,
			Status:  v1alpha1.ConditionTrue,
			Reason:  upstreamwatchers.ReasonUsingConfigurationFromSpec,
			Message: "Using search base from ActiveDirectoryIdentityProvider config.",
		}
	}
	ldapProvider := upstreamldap.New(*config)
	// Query your AD server for the defaultNamingContext to get a DN to use as the search base
	// when it isn't specified.
	// https://ldapwiki.com/wiki/DefaultNamingContext
	defaultNamingContext, err := ldapProvider.SearchForDefaultNamingContext(ctx)
	if err != nil {
		return &v1alpha1.Condition{
			Type:    upstreamwatchers.TypeSearchBaseFound,
			Status:  v1alpha1.ConditionFalse,
			Reason:  upstreamwatchers.ReasonErrorFetchingSearchBase,
			Message: fmt.Sprintf(`Error finding search base: %s`, err.Error()),
		}
	}
	if config.UserSearch.Base == "" {
		config.UserSearch.Base = defaultNamingContext
	}
	if config.GroupSearch.Base == "" {
		config.GroupSearch.Base = defaultNamingContext
	}
	return &v1alpha1.Condition{
		Type:    upstreamwatchers.TypeSearchBaseFound,
		Status:  v1alpha1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: "Successfully fetched defaultNamingContext to use as default search base from RootDSE.",
	}
}

type activeDirectoryUpstreamGenericLDAPUserSearch struct {
	userSearch v1alpha1.ActiveDirectoryIdentityProviderUserSearch
}

func (u *activeDirectoryUpstreamGenericLDAPUserSearch) Base() string {
	return u.userSearch.Base
}

func (u *activeDirectoryUpstreamGenericLDAPUserSearch) Filter() string {
	if len(u.userSearch.Filter) == 0 {
		return defaultActiveDirectoryUserSearchFilter
	}
	return u.userSearch.Filter
}

func (u *activeDirectoryUpstreamGenericLDAPUserSearch) UsernameAttribute() string {
	if len(u.userSearch.Attributes.Username) == 0 {
		return defaultActiveDirectoryUsernameAttributeName
	}
	return u.userSearch.Attributes.Username
}

func (u *activeDirectoryUpstreamGenericLDAPUserSearch) UIDAttribute() string {
	if len(u.userSearch.Attributes.UID) == 0 {
		return defaultActiveDirectoryUIDAttributeName
	}
	return u.userSearch.Attributes.UID
}

type activeDirectoryUpstreamGenericLDAPGroupSearch struct {
	groupSearch v1alpha1.ActiveDirectoryIdentityProviderGroupSearch
}

func (g *activeDirectoryUpstreamGenericLDAPGroupSearch) Base() string {
	return g.groupSearch.Base
}

func (g *activeDirectoryUpstreamGenericLDAPGroupSearch) Filter() string {
	if len(g.groupSearch.Filter) == 0 {
		return defaultActiveDirectoryGroupSearchFilter
	}
	return g.groupSearch.Filter
}

func (g *activeDirectoryUpstreamGenericLDAPGroupSearch) GroupNameAttribute() string {
	if len(g.groupSearch.Attributes.GroupName) == 0 {
		return defaultActiveDirectoryGroupNameAttributeName
	}
	return g.groupSearch.Attributes.GroupName
}

type activeDirectoryUpstreamGenericLDAPStatus struct {
	activeDirectoryIdentityProvider v1alpha1.ActiveDirectoryIdentityProvider
}

func (s *activeDirectoryUpstreamGenericLDAPStatus) Conditions() []v1alpha1.Condition {
	return s.activeDirectoryIdentityProvider.Status.Conditions
}

// UpstreamActiveDirectoryIdentityProviderICache is a thread safe cache that holds a list of validated upstream LDAP IDP configurations.
type UpstreamActiveDirectoryIdentityProviderICache interface {
	SetActiveDirectoryIdentityProviders([]provider.UpstreamLDAPIdentityProviderI)
}

type activeDirectoryWatcherController struct {
	cache                                   UpstreamActiveDirectoryIdentityProviderICache
	validatedSecretVersionsCache            upstreamwatchers.SecretVersionCacheI
	ldapDialer                              upstreamldap.LDAPDialer
	client                                  pinnipedclientset.Interface
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer
	secretInformer                          corev1informers.SecretInformer
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamActiveDirectoryIdentityProviderICache.
func New(
	idpCache UpstreamActiveDirectoryIdentityProviderICache,
	client pinnipedclientset.Interface,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return newInternal(
		idpCache,
		// start with an empty secretVersionCache
		upstreamwatchers.NewSecretVersionCache(),
		// nil means to use a real production dialer when creating objects to add to the cache
		nil,
		client,
		activeDirectoryIdentityProviderInformer,
		secretInformer,
		withInformer,
	)
}

// For test dependency injection purposes.
func newInternal(
	idpCache UpstreamActiveDirectoryIdentityProviderICache,
	validatedSecretVersionsCache upstreamwatchers.SecretVersionCacheI,
	ldapDialer upstreamldap.LDAPDialer,
	client pinnipedclientset.Interface,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	c := activeDirectoryWatcherController{
		cache:                                   idpCache,
		validatedSecretVersionsCache:            validatedSecretVersionsCache,
		ldapDialer:                              ldapDialer,
		client:                                  client,
		activeDirectoryIdentityProviderInformer: activeDirectoryIdentityProviderInformer,
		secretInformer:                          secretInformer,
	}
	return controllerlib.New(
		controllerlib.Config{Name: activeDirectoryControllerName, Syncer: &c},
		withInformer(
			activeDirectoryIdentityProviderInformer,
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
func (c *activeDirectoryWatcherController) Sync(ctx controllerlib.Context) error {
	actualUpstreams, err := c.activeDirectoryIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list ActiveDirectoryIdentityProviders: %w", err)
	}

	requeue := false
	validatedUpstreams := make([]provider.UpstreamLDAPIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		valid, requestedRequeue := c.validateUpstream(ctx.Context, upstream)
		if valid != nil {
			validatedUpstreams = append(validatedUpstreams, valid)
		}
		if requestedRequeue {
			requeue = true
		}
	}

	c.cache.SetActiveDirectoryIdentityProviders(validatedUpstreams)

	if requeue {
		return controllerlib.ErrSyntheticRequeue
	}
	return nil
}

func (c *activeDirectoryWatcherController) validateUpstream(ctx context.Context, upstream *v1alpha1.ActiveDirectoryIdentityProvider) (p provider.UpstreamLDAPIdentityProviderI, requeue bool) {
	spec := upstream.Spec

	adUpstreamImpl := &activeDirectoryUpstreamGenericLDAPImpl{activeDirectoryIdentityProvider: *upstream}

	config := &upstreamldap.ProviderConfig{
		Name:        upstream.Name,
		ResourceUID: upstream.UID,
		Host:        spec.Host,
		UserSearch: upstreamldap.UserSearchConfig{
			Base:              spec.UserSearch.Base,
			Filter:            adUpstreamImpl.Spec().UserSearch().Filter(),
			UsernameAttribute: adUpstreamImpl.Spec().UserSearch().UsernameAttribute(),
			UIDAttribute:      adUpstreamImpl.Spec().UserSearch().UIDAttribute(),
		},
		GroupSearch: upstreamldap.GroupSearchConfig{
			Base:               spec.GroupSearch.Base,
			Filter:             adUpstreamImpl.Spec().GroupSearch().Filter(),
			GroupNameAttribute: adUpstreamImpl.Spec().GroupSearch().GroupNameAttribute(),
		},
		Dialer:                       c.ldapDialer,
		UIDAttributeParsingOverrides: map[string]func(*ldap.Entry) (string, error){"objectGUID": upstreamldap.MicrosoftUUIDFromBinary("objectGUID")},
		RefreshAttributeChecks:       map[string]func(*ldap.Entry, provider.StoredRefreshAttributes) error{"pwdLastSet": upstreamldap.PwdUnchangedSinceLogin},
	}

	if spec.GroupSearch.Attributes.GroupName == "" {
		config.GroupAttributeParsingOverrides = map[string]func(*ldap.Entry) (string, error){defaultActiveDirectoryGroupNameAttributeName: upstreamldap.GroupSAMAccountNameWithDomainSuffix}
	}

	conditions := upstreamwatchers.ValidateGenericLDAP(ctx, adUpstreamImpl, c.secretInformer, c.validatedSecretVersionsCache, config)

	c.updateStatus(ctx, upstream, conditions.Conditions())

	return upstreamwatchers.EvaluateConditions(conditions, config)
}

func (c *activeDirectoryWatcherController) updateStatus(ctx context.Context, upstream *v1alpha1.ActiveDirectoryIdentityProvider, conditions []*v1alpha1.Condition) {
	log := klogr.New().WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.Merge(conditions, upstream.Generation, &updated.Status.Conditions, log)

	updated.Status.Phase = v1alpha1.ActiveDirectoryPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = v1alpha1.ActiveDirectoryPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return // nothing to update
	}

	_, err := c.client.
		IDPV1alpha1().
		ActiveDirectoryIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		log.Error(err, "failed to update status")
	}
}
