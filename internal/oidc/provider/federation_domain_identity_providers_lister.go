// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/oidc/idplister"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/psession"
)

// FederationDomainIdentityProvider represents an identity provider as configured in a FederationDomain's spec.
// All the fields are required and must be non-zero values. Note that this might be a reference to an IDP
// which is not currently loaded into the cache of available IDPs, e.g. due to the IDP's CR having validation errors.
type FederationDomainIdentityProvider struct {
	DisplayName string
	UID         types.UID
	Transforms  *idtransform.TransformationPipeline
}

// FederationDomainResolvedOIDCIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamOIDCIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedOIDCIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamOIDCIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

// FederationDomainResolvedLDAPIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamLDAPIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedLDAPIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamLDAPIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

type FederationDomainIdentityProvidersFinderI interface {
	FindDefaultIDP() (
		*FederationDomainResolvedOIDCIdentityProvider,
		*FederationDomainResolvedLDAPIdentityProvider,
		error,
	)

	FindUpstreamIDPByDisplayName(upstreamIDPDisplayName string) (
		*FederationDomainResolvedOIDCIdentityProvider,
		*FederationDomainResolvedLDAPIdentityProvider,
		error,
	)
}

type FederationDomainIdentityProvidersListerI interface {
	GetOIDCIdentityProviders() []*FederationDomainResolvedOIDCIdentityProvider
	GetLDAPIdentityProviders() []*FederationDomainResolvedLDAPIdentityProvider
	GetActiveDirectoryIdentityProviders() []*FederationDomainResolvedLDAPIdentityProvider
}

// FederationDomainIdentityProvidersLister wraps an UpstreamIdentityProvidersLister. The lister which is being
// wrapped should contain all valid upstream providers that are currently defined in the Supervisor.
// FederationDomainIdentityProvidersLister provides a lookup method which only looks up IDPs within those which
// have allowed resource IDs, and also uses display names (name aliases) instead of the actual resource names to do the
// lookups. It also provides list methods which only list the allowed identity providers (to be used by the IDP
// discovery endpoint, for example).
type FederationDomainIdentityProvidersLister struct {
	wrappedLister                    idplister.UpstreamIdentityProvidersLister
	configuredIdentityProviders      []*FederationDomainIdentityProvider
	defaultIdentityProvider          *FederationDomainIdentityProvider
	idpDisplayNamesToResourceUIDsMap map[string]types.UID
	allowedIDPResourceUIDs           sets.Set[types.UID]
}

// NewFederationDomainUpstreamIdentityProvidersLister returns a new FederationDomainIdentityProvidersLister
// which only lists those IDPs allowed by its parameter. Every FederationDomainIdentityProvider in the
// federationDomainIssuer parameter's IdentityProviders() list must have a unique DisplayName.
// Note that a single underlying IDP UID may be used by multiple FederationDomainIdentityProvider in the parameter.
// The wrapped lister should contain all valid upstream providers that are defined in the Supervisor, and is expected to
// be thread-safe and to change its contents over time. The FederationDomainIdentityProvidersLister will filter out the
// ones that don't apply to this federation domain.
func NewFederationDomainUpstreamIdentityProvidersLister(
	federationDomainIssuer *FederationDomainIssuer,
	wrappedLister idplister.UpstreamIdentityProvidersLister,
) *FederationDomainIdentityProvidersLister {
	// Create a copy of the input slice so we won't need to worry about the caller accidentally changing it.
	copyOfFederationDomainIdentityProviders := []*FederationDomainIdentityProvider{}
	// Create a map and a set for quick lookups of the same data that was passed in via the
	// federationDomainIssuer parameter.
	allowedResourceUIDs := sets.New[types.UID]()
	idpDisplayNamesToResourceUIDsMap := map[string]types.UID{}
	for _, idp := range federationDomainIssuer.IdentityProviders() {
		allowedResourceUIDs.Insert(idp.UID)
		idpDisplayNamesToResourceUIDsMap[idp.DisplayName] = idp.UID
		shallowCopyOfIDP := *idp
		copyOfFederationDomainIdentityProviders = append(copyOfFederationDomainIdentityProviders, &shallowCopyOfIDP)
	}

	return &FederationDomainIdentityProvidersLister{
		wrappedLister:                    wrappedLister,
		configuredIdentityProviders:      copyOfFederationDomainIdentityProviders,
		defaultIdentityProvider:          federationDomainIssuer.DefaultIdentityProvider(),
		idpDisplayNamesToResourceUIDsMap: idpDisplayNamesToResourceUIDsMap,
		allowedIDPResourceUIDs:           allowedResourceUIDs,
	}
}

// FindUpstreamIDPByDisplayName selects either an OIDC, LDAP, or ActiveDirectory IDP, or returns an error.
// It only considers the allowed IDPs while doing the lookup by display name.
// Note that ActiveDirectory and LDAP IDPs both return the same type, but with different SessionProviderType values.
func (u *FederationDomainIdentityProvidersLister) FindUpstreamIDPByDisplayName(upstreamIDPDisplayName string) (
	*FederationDomainResolvedOIDCIdentityProvider,
	*FederationDomainResolvedLDAPIdentityProvider,
	error,
) {
	// Given a display name, look up the identity provider's UID for that display name.
	idpUIDForDisplayName, ok := u.idpDisplayNamesToResourceUIDsMap[upstreamIDPDisplayName]
	if !ok {
		return nil, nil, fmt.Errorf("identity provider not found: %q", upstreamIDPDisplayName)
	}
	// Find the IDP with that UID. It could be any type, so look at all types to find it.
	for _, p := range u.GetOIDCIdentityProviders() {
		if p.Provider.GetResourceUID() == idpUIDForDisplayName {
			return p, nil, nil
		}
	}
	for _, p := range u.GetLDAPIdentityProviders() {
		if p.Provider.GetResourceUID() == idpUIDForDisplayName {
			return nil, p, nil
		}
	}
	for _, p := range u.GetActiveDirectoryIdentityProviders() {
		if p.Provider.GetResourceUID() == idpUIDForDisplayName {
			return nil, p, nil
		}
	}
	return nil, nil, fmt.Errorf("identity provider not found: %q", upstreamIDPDisplayName)
}

// FindDefaultIDP works like FindUpstreamIDPByDisplayName, but finds the default IDP instead of finding by name.
// If there is no default IDP for this federation domain, then FindDefaultIDP will return an error.
// This can be used to handle the backwards compatibility mode where an authorization request could be made
// without specifying an IDP name, and there are no IDPs explicitly specified on the FederationDomain, and there
// is exactly one IDP CR defined in the Supervisor namespace.
func (u *FederationDomainIdentityProvidersLister) FindDefaultIDP() (
	*FederationDomainResolvedOIDCIdentityProvider,
	*FederationDomainResolvedLDAPIdentityProvider,
	error,
) {
	if u.defaultIdentityProvider == nil {
		return nil, nil, fmt.Errorf("identity provider not found: this federation domain does not have a default identity provider")
	}
	return u.FindUpstreamIDPByDisplayName(u.defaultIdentityProvider.DisplayName)
}

// GetOIDCIdentityProviders lists only the OIDC providers for this FederationDomain.
func (u *FederationDomainIdentityProvidersLister) GetOIDCIdentityProviders() []*FederationDomainResolvedOIDCIdentityProvider {
	// Get the cached providers once at the start in case they change during the rest of this function.
	cachedProviders := u.wrappedLister.GetOIDCIdentityProviders()
	providers := []*FederationDomainResolvedOIDCIdentityProvider{}
	// Every configured identityProvider on the FederationDomain uses an objetRef to an underlying IDP CR that might
	// be available as a provider in the wrapped cache. For each configured identityProvider/displayName...
	for _, idp := range u.configuredIdentityProviders {
		// Check if the IDP used by that displayName is in the cached available OIDC providers.
		for _, p := range cachedProviders {
			if idp.UID == p.GetResourceUID() {
				// Found it, so append it to the result.
				providers = append(providers, &FederationDomainResolvedOIDCIdentityProvider{
					DisplayName:         idp.DisplayName,
					Provider:            p,
					SessionProviderType: psession.ProviderTypeOIDC,
					Transforms:          idp.Transforms,
				})
			}
		}
	}
	return providers
}

// GetLDAPIdentityProviders lists only the LDAP providers for this FederationDomain.
func (u *FederationDomainIdentityProvidersLister) GetLDAPIdentityProviders() []*FederationDomainResolvedLDAPIdentityProvider {
	// Get the cached providers once at the start in case they change during the rest of this function.
	cachedProviders := u.wrappedLister.GetLDAPIdentityProviders()
	providers := []*FederationDomainResolvedLDAPIdentityProvider{}
	// Every configured identityProvider on the FederationDomain uses an objetRef to an underlying IDP CR that might
	// be available as a provider in the wrapped cache. For each configured identityProvider/displayName...
	for _, idp := range u.configuredIdentityProviders {
		// Check if the IDP used by that displayName is in the cached available LDAP providers.
		for _, p := range cachedProviders {
			if idp.UID == p.GetResourceUID() {
				// Found it, so append it to the result.
				providers = append(providers, &FederationDomainResolvedLDAPIdentityProvider{
					DisplayName:         idp.DisplayName,
					Provider:            p,
					SessionProviderType: psession.ProviderTypeLDAP,
					Transforms:          idp.Transforms,
				})
			}
		}
	}
	return providers
}

// GetActiveDirectoryIdentityProviders lists only the ActiveDirectory providers for this FederationDomain.
func (u *FederationDomainIdentityProvidersLister) GetActiveDirectoryIdentityProviders() []*FederationDomainResolvedLDAPIdentityProvider {
	// Get the cached providers once at the start in case they change during the rest of this function.
	cachedProviders := u.wrappedLister.GetActiveDirectoryIdentityProviders()
	providers := []*FederationDomainResolvedLDAPIdentityProvider{}
	// Every configured identityProvider on the FederationDomain uses an objetRef to an underlying IDP CR that might
	// be available as a provider in the wrapped cache. For each configured identityProvider/displayName...
	for _, idp := range u.configuredIdentityProviders {
		// Check if the IDP used by that displayName is in the cached available ActiveDirectory providers.
		for _, p := range cachedProviders {
			if idp.UID == p.GetResourceUID() {
				// Found it, so append it to the result.
				providers = append(providers, &FederationDomainResolvedLDAPIdentityProvider{
					DisplayName:         idp.DisplayName,
					Provider:            p,
					SessionProviderType: psession.ProviderTypeActiveDirectory,
					Transforms:          idp.Transforms,
				})
			}
		}
	}
	return providers
}
