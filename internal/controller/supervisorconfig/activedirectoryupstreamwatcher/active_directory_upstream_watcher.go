// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package activedirectoryupstreamwatcher implements a controller which watches ActiveDirectoryIdentityProviders.
package activedirectoryupstreamwatcher

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
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

	sAMAccountNameAttribute = "sAMAccountName"
	// pwdLastSetAttribute is the date and time that the password for this account was last changed.
	// https://docs.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset
	pwdLastSetAttribute = "pwdLastSet"
	// userAccountControlAttribute represents a bitmap of user properties.
	// https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
	userAccountControlAttribute = "userAccountControl"
	// userAccountControlComputedAttribute represents a bitmap of user properties.
	// https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed
	userAccountControlComputedAttribute = "msDS-User-Account-Control-Computed"
	// 0x0002 ACCOUNTDISABLE in userAccountControl bitmap.
	accountDisabledBitmapValue = 2
	// 0x0010 UF_LOCKOUT in msDS-User-Account-Control-Computed bitmap.
	accountLockedBitmapValue = 16
)

type activeDirectoryUpstreamGenericLDAPImpl struct {
	activeDirectoryIdentityProvider idpv1alpha1.ActiveDirectoryIdentityProvider
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
	activeDirectoryIdentityProvider idpv1alpha1.ActiveDirectoryIdentityProvider
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) Host() string {
	return s.activeDirectoryIdentityProvider.Spec.Host
}

func (s *activeDirectoryUpstreamGenericLDAPSpec) TLSSpec() *idpv1alpha1.TLSSpec {
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

func (s *activeDirectoryUpstreamGenericLDAPSpec) DetectAndSetSearchBase(ctx context.Context, config *upstreamldap.ProviderConfig) *metav1.Condition {
	config.GroupSearch.Base = s.activeDirectoryIdentityProvider.Spec.GroupSearch.Base
	config.UserSearch.Base = s.activeDirectoryIdentityProvider.Spec.UserSearch.Base
	if config.GroupSearch.Base != "" && config.UserSearch.Base != "" {
		// Both were already set in spec so just return; no need to query the RootDSE
		return &metav1.Condition{
			Type:    upstreamwatchers.TypeSearchBaseFound,
			Status:  metav1.ConditionTrue,
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
		return &metav1.Condition{
			Type:    upstreamwatchers.TypeSearchBaseFound,
			Status:  metav1.ConditionFalse,
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
	return &metav1.Condition{
		Type:    upstreamwatchers.TypeSearchBaseFound,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "Successfully fetched defaultNamingContext to use as default search base from RootDSE.",
	}
}

type activeDirectoryUpstreamGenericLDAPUserSearch struct {
	userSearch idpv1alpha1.ActiveDirectoryIdentityProviderUserSearch
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
	groupSearch idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearch
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

func (g *activeDirectoryUpstreamGenericLDAPGroupSearch) UserAttributeForFilter() string {
	return g.groupSearch.UserAttributeForFilter
}

func (g *activeDirectoryUpstreamGenericLDAPGroupSearch) GroupNameAttribute() string {
	if len(g.groupSearch.Attributes.GroupName) == 0 {
		return defaultActiveDirectoryGroupNameAttributeName
	}
	return g.groupSearch.Attributes.GroupName
}

type activeDirectoryUpstreamGenericLDAPStatus struct {
	activeDirectoryIdentityProvider idpv1alpha1.ActiveDirectoryIdentityProvider
}

func (s *activeDirectoryUpstreamGenericLDAPStatus) Conditions() []metav1.Condition {
	return s.activeDirectoryIdentityProvider.Status.Conditions
}

// UpstreamActiveDirectoryIdentityProviderICache is a thread safe cache that holds a list of validated upstream LDAP IDP configurations.
type UpstreamActiveDirectoryIdentityProviderICache interface {
	SetActiveDirectoryIdentityProviders([]upstreamprovider.UpstreamLDAPIdentityProviderI)
}

type activeDirectoryWatcherController struct {
	cache                                   UpstreamActiveDirectoryIdentityProviderICache
	validatedSettingsCache                  upstreamwatchers.ValidatedSettingsCacheI
	ldapDialer                              upstreamldap.LDAPDialer
	client                                  supervisorclientset.Interface
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer
	secretInformer                          corev1informers.SecretInformer
	configMapInformer                       corev1informers.ConfigMapInformer
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamActiveDirectoryIdentityProviderICache.
func New(
	idpCache UpstreamActiveDirectoryIdentityProviderICache,
	client supervisorclientset.Interface,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return newInternal(
		idpCache,
		// start with an empty cache
		upstreamwatchers.NewValidatedSettingsCache(),
		// nil means to use a real production dialer when creating objects to add to the cache
		nil,
		client,
		activeDirectoryIdentityProviderInformer,
		secretInformer,
		configMapInformer,
		withInformer,
	)
}

// For test dependency injection purposes.
func newInternal(
	idpCache UpstreamActiveDirectoryIdentityProviderICache,
	validatedSettingsCache upstreamwatchers.ValidatedSettingsCacheI,
	ldapDialer upstreamldap.LDAPDialer,
	client supervisorclientset.Interface,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	c := activeDirectoryWatcherController{
		cache:                                   idpCache,
		validatedSettingsCache:                  validatedSettingsCache,
		ldapDialer:                              ldapDialer,
		client:                                  client,
		activeDirectoryIdentityProviderInformer: activeDirectoryIdentityProviderInformer,
		secretInformer:                          secretInformer,
		configMapInformer:                       configMapInformer,
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
	validatedUpstreams := make([]upstreamprovider.UpstreamLDAPIdentityProviderI, 0, len(actualUpstreams))
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

func (c *activeDirectoryWatcherController) validateUpstream(ctx context.Context, upstream *idpv1alpha1.ActiveDirectoryIdentityProvider) (p upstreamprovider.UpstreamLDAPIdentityProviderI, requeue bool) {
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
			Base:                   spec.GroupSearch.Base,
			Filter:                 adUpstreamImpl.Spec().GroupSearch().Filter(),
			UserAttributeForFilter: adUpstreamImpl.Spec().GroupSearch().UserAttributeForFilter(),
			GroupNameAttribute:     adUpstreamImpl.Spec().GroupSearch().GroupNameAttribute(),
			SkipGroupRefresh:       spec.GroupSearch.SkipGroupRefresh,
		},
		Dialer: c.ldapDialer,
		UIDAttributeParsingOverrides: map[string]func(*ldap.Entry) (string, error){
			"objectGUID": microsoftUUIDFromBinaryAttr("objectGUID"),
		},
		RefreshAttributeChecks: map[string]func(*ldap.Entry, upstreamprovider.LDAPRefreshAttributes) error{
			pwdLastSetAttribute:                 attributeUnchangedSinceLogin(pwdLastSetAttribute),
			userAccountControlAttribute:         validUserAccountControl,
			userAccountControlComputedAttribute: validComputedUserAccountControl,
		},
	}

	if spec.GroupSearch.Attributes.GroupName == "" {
		config.GroupAttributeParsingOverrides = map[string]func(*ldap.Entry) (string, error){
			defaultActiveDirectoryGroupNameAttributeName: groupSAMAccountNameWithDomainSuffix,
		}
	}

	conditions := upstreamwatchers.ValidateGenericLDAP(ctx, adUpstreamImpl, c.secretInformer, c.configMapInformer, c.validatedSettingsCache, config)

	c.updateStatus(ctx, upstream, conditions.Conditions())

	return upstreamwatchers.EvaluateConditions(conditions, config)
}

func (c *activeDirectoryWatcherController) updateStatus(ctx context.Context, upstream *idpv1alpha1.ActiveDirectoryIdentityProvider, conditions []*metav1.Condition) {
	log := plog.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(conditions, upstream.Generation, &updated.Status.Conditions, log, metav1.Now())

	updated.Status.Phase = idpv1alpha1.ActiveDirectoryPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = idpv1alpha1.ActiveDirectoryPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return // nothing to update
	}

	_, err := c.client.
		IDPV1alpha1().
		ActiveDirectoryIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		log.Error("failed to update status", err)
	}
}

//nolint:gochecknoglobals // this needs to be a global variable so that tests can check pointer equality
var microsoftUUIDFromBinaryAttr = func(attributeName string) func(*ldap.Entry) (string, error) {
	// validation has already been done so we can just get the attribute...
	return func(entry *ldap.Entry) (string, error) {
		binaryUUID := entry.GetRawAttributeValue(attributeName)
		return microsoftUUIDFromBinary(binaryUUID)
	}
}

func microsoftUUIDFromBinary(binaryUUID []byte) (string, error) {
	uuidVal, err := uuid.FromBytes(binaryUUID) // start out with the RFC4122 version
	if err != nil {
		return "", err
	}
	// then swap it because AD stores the first 3 fields little-endian rather than the expected
	// big-endian.
	uuidVal[0], uuidVal[1], uuidVal[2], uuidVal[3] = uuidVal[3], uuidVal[2], uuidVal[1], uuidVal[0]
	uuidVal[4], uuidVal[5] = uuidVal[5], uuidVal[4]
	uuidVal[6], uuidVal[7] = uuidVal[7], uuidVal[6]
	return uuidVal.String(), nil
}

func groupSAMAccountNameWithDomainSuffix(entry *ldap.Entry) (string, error) {
	sAMAccountNameAttributeValues := entry.GetAttributeValues(sAMAccountNameAttribute)

	if len(sAMAccountNameAttributeValues) != 1 {
		return "", fmt.Errorf(`found %d values for attribute %q, but expected 1 result`,
			len(sAMAccountNameAttributeValues), sAMAccountNameAttribute,
		)
	}

	sAMAccountName := sAMAccountNameAttributeValues[0]
	if len(sAMAccountName) == 0 {
		return "", fmt.Errorf(`found empty value for attribute %q, but expected value to be non-empty`,
			sAMAccountNameAttribute,
		)
	}

	distinguishedName := entry.DN
	domain, err := getDomainFromDistinguishedName(distinguishedName)
	if err != nil {
		return "", err
	}
	return sAMAccountName + "@" + domain, nil
}

var domainComponentsRegexp = regexp.MustCompile(",DC=|,dc=")

func getDomainFromDistinguishedName(distinguishedName string) (string, error) {
	domainComponents := domainComponentsRegexp.Split(distinguishedName, -1)
	if len(domainComponents) == 1 {
		return "", fmt.Errorf("did not find domain components in group dn: %s", distinguishedName)
	}
	return strings.Join(domainComponents[1:], "."), nil
}

//nolint:gochecknoglobals // this needs to be a global variable so that tests can check pointer equality
var validUserAccountControl = func(entry *ldap.Entry, _ upstreamprovider.LDAPRefreshAttributes) error {
	userAccountControl, err := strconv.Atoi(entry.GetAttributeValue(userAccountControlAttribute))
	if err != nil {
		return err
	}

	deactivated := userAccountControl & accountDisabledBitmapValue // bitwise and.
	if deactivated != 0 {
		return fmt.Errorf("user has been deactivated")
	}
	return nil
}

//nolint:gochecknoglobals // this needs to be a global variable so that tests can check pointer equality
var validComputedUserAccountControl = func(entry *ldap.Entry, _ upstreamprovider.LDAPRefreshAttributes) error {
	userAccountControl, err := strconv.Atoi(entry.GetAttributeValue(userAccountControlComputedAttribute))
	if err != nil {
		return err
	}

	locked := userAccountControl & accountLockedBitmapValue // bitwise and
	if locked != 0 {
		return fmt.Errorf("user has been locked")
	}
	return nil
}

//nolint:gochecknoglobals // this needs to be a global variable so that tests can check pointer equality
var attributeUnchangedSinceLogin = func(attribute string) func(*ldap.Entry, upstreamprovider.LDAPRefreshAttributes) error {
	return func(entry *ldap.Entry, storedAttributes upstreamprovider.LDAPRefreshAttributes) error {
		prevAttributeValue := storedAttributes.AdditionalAttributes[attribute]
		newValues := entry.GetRawAttributeValues(attribute)

		if len(newValues) != 1 {
			return fmt.Errorf(`expected to find 1 value for %q attribute, but found %d`, attribute, len(newValues))
		}
		encodedNewValue := base64.RawURLEncoding.EncodeToString(newValues[0])
		if prevAttributeValue != encodedNewValue {
			return fmt.Errorf(`value for attribute %q has changed since initial value at login`, attribute)
		}
		return nil
	}
}
