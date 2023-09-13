// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package federationdomainproviders

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/idplister"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestFederationDomainIdentityProvidersListerFinder(t *testing.T) {
	// IdPs
	myDefaultOIDCIDP := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName("my-default-oidc-idp").
		WithResourceUID("my-default-oidc-uid-idp").
		Build()
	myOIDCIDP1 := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName("my-oidc-idp1").
		WithResourceUID("my-oidc-uid-idp1").
		Build()
	myOIDCIDP2 := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
		WithName("my-oidc-idp2").
		WithResourceUID("my-oidc-uid-idp2").
		Build()

	myDefaultLDAPIDP := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName("my-default-ldap-idp").
		WithResourceUID("my-default-ldap-uid-idp").
		Build()
	myLDAPIDP1 := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName("my-ldap-idp1").
		WithResourceUID("my-ldap-uid-idp1").
		Build()
	myLDAPIDP2 := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName("my-ldap-idp2").
		WithResourceUID("my-ldap-uid-idp2").
		Build()

	myADIDP1 := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName("my-ad-idp1").
		WithResourceUID("my-ad-uid-idp1").
		Build()
	myADIDP2 := oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
		WithName("my-ad-idp2").
		WithResourceUID("my-ad-uid-idp2").
		Build()

	// FederationDomainIssuers
	fakeIssuerURL := "https://www.fakeissuerurl.com"
	fdIssuerWithoutIDP, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{})
	require.NoError(t, err)
	fdIssuerWithDefaultOIDCIDP, err := NewFederationDomainIssuerWithDefaultIDP(fakeIssuerURL, &FederationDomainIdentityProvider{
		DisplayName: "my-default-oidc-idp",
		UID:         "my-default-oidc-uid-idp",
	})
	require.NoError(t, err)
	fdIssuerWithDefaultLDAPIDP, err := NewFederationDomainIssuerWithDefaultIDP(fakeIssuerURL, &FederationDomainIdentityProvider{
		DisplayName: "my-default-ldap-idp",
		UID:         "my-default-ldap-uid-idp",
	})
	require.NoError(t, err)
	fdIssuerWithOIDCIDP1, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-oidc-idp1", UID: "my-oidc-uid-idp1"},
	})
	require.NoError(t, err)
	fdIssuerWithOIDCIDP2, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-oidc-idp1", UID: "my-oidc-uid-idp1"},
		{DisplayName: "my-oidc-idp2", UID: "my-oidc-uid-idp2"},
	})
	require.NoError(t, err)

	fdIssuerWithOIDCAndLDAPAndADIDPs, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-oidc-idp1", UID: "my-oidc-uid-idp1"},
		{DisplayName: "my-oidc-idp2", UID: "my-oidc-uid-idp2"},
		{DisplayName: "my-ldap-idp1", UID: "my-ldap-uid-idp1"},
		{DisplayName: "my-ldap-idp2", UID: "my-ldap-uid-idp2"},
		{DisplayName: "my-ad-idp1", UID: "my-ad-uid-idp1"},
		{DisplayName: "my-ad-idp2", UID: "my-ad-uid-idp2"},
	})
	require.NoError(t, err)

	fdIssuerWithLotsOfIDPs, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-oidc-idp1", UID: "my-oidc-uid-idp1"},
		{DisplayName: "my-oidc-idp2", UID: "my-oidc-uid-idp2"},
		{DisplayName: "my-ldap-idp1", UID: "my-ldap-uid-idp1"},
		{DisplayName: "my-ldap-idp2", UID: "my-ldap-uid-idp2"},
		{DisplayName: "my-ad-idp1", UID: "my-ad-uid-idp1"},
		{DisplayName: "my-oidc-idp3", UID: "my-oidc-uid-idp3"},
		{DisplayName: "my-oidc-idp4", UID: "my-oidc-uid-idp4"},
		{DisplayName: "my-ldap-idp3", UID: "my-ldap-uid-idp3"},
		{DisplayName: "my-ldap-idp4", UID: "my-ldap-uid-idp4"},
		{DisplayName: "my-ad-idp2", UID: "my-ad-uid-idp2"},
		{DisplayName: "my-ad-idp3", UID: "my-ad-uid-idp3"},
	})
	require.NoError(t, err)

	fdIssuerWithIDPwithLostUID, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-idp", UID: "you-cant-find-my-uid"},
	})
	require.NoError(t, err)

	// Resolved IdPs
	myOIDCIDP1Resolved := &resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-oidc-idp1",
		Provider:            myOIDCIDP1,
		SessionProviderType: "oidc",
	}
	myOIDCIDP2Resolved := &resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-oidc-idp2",
		Provider:            myOIDCIDP2,
		SessionProviderType: "oidc",
	}
	myLDAPIDP1Resolved := &resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ldap-idp1",
		Provider:            myLDAPIDP1,
		SessionProviderType: "ldap",
	}
	myLDAPIDP2Resolved := &resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ldap-idp2",
		Provider:            myLDAPIDP2,
		SessionProviderType: "ldap",
	}
	myADIDP1Resolved := &resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ad-idp1",
		Provider:            myADIDP1,
		SessionProviderType: "activedirectory",
	}
	myADIDP2Resolved := &resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ad-idp2",
		Provider:            myADIDP2,
		SessionProviderType: "activedirectory",
	}

	myDefaultOIDCIDPResolved := &resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-default-oidc-idp",
		Provider:            myDefaultOIDCIDP,
		SessionProviderType: "oidc",
	}
	myDefaultLDAPIDPResolved := &resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-default-ldap-idp",
		Provider:            myDefaultLDAPIDP,
		SessionProviderType: "ldap",
	}

	testFindUpstreamIDPByDisplayName := []struct {
		name                     string
		wrappedLister            idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer   *FederationDomainIssuer
		findIDPByDisplayName     string
		wantOIDCIDPByDisplayName *resolvedprovider.FederationDomainResolvedOIDCIdentityProvider
		wantLDAPIDPByDisplayName *resolvedprovider.FederationDomainResolvedLDAPIdentityProvider
		wantError                string
	}{
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IdP by display name with one IDP configured",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithLDAP(myLDAPIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP1,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP by display name if multiple IDPs configured of the same type",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP2,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP by display name if multiple IDPs configured of different types",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type OIDC by display name",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP1,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type LDAP by display name",
			findIDPByDisplayName: "my-ldap-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type AD (LDAP)  by display name",
			findIDPByDisplayName: "my-ad-idp1",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantLDAPIDPByDisplayName: myADIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will error if IDP by display name is not found - no such display name",
			findIDPByDisplayName: "i-cant-find-my-idp",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantError:              `identity provider not found: "i-cant-find-my-idp"`,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will error if IDP by display name is not found - display name was found, but IDP it points at does not exist",
			findIDPByDisplayName: "my-idp",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithIDPwithLostUID,
			wantError:              `identity provider not available: "my-idp"`,
		},
	}

	for _, tt := range testFindUpstreamIDPByDisplayName {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			foundOIDCIDP, foundLDAPIDP, err := subject.FindUpstreamIDPByDisplayName(tt.findIDPByDisplayName)

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			if tt.wantOIDCIDPByDisplayName != nil {
				require.Equal(t, foundOIDCIDP, tt.wantOIDCIDPByDisplayName)
			}
			if tt.wantLDAPIDPByDisplayName != nil {
				require.Equal(t, foundLDAPIDP, tt.wantLDAPIDPByDisplayName)
			}
		})
	}

	testFindDefaultIDP := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantDefaultOIDCIDP     *resolvedprovider.FederationDomainResolvedOIDCIdentityProvider
		wantDefaultLDAPIDP     *resolvedprovider.FederationDomainResolvedLDAPIdentityProvider
		wantError              string
	}{
		{
			name: "FindDefaultIDP returns an OIDCIdentityProvider if there is an OIDCIdentityProvider defined as the default IDP",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myDefaultOIDCIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultOIDCIDP,
			wantDefaultOIDCIDP:     myDefaultOIDCIDPResolved,
		},
		{
			name: "FindDefaultIDP returns an LDAPIdentityProvider if there is an LDAPIdentityProvider defined as the default IDP",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithLDAP(myDefaultLDAPIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultLDAPIDP,
			wantDefaultLDAPIDP:     myDefaultLDAPIDPResolved,
		},
		{
			name: "FindDefaultIDP returns an error if there is no default IDP to return",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithLDAP(myDefaultLDAPIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithoutIDP,
			wantError:              "identity provider not found: this federation domain does not have a default identity provider",
		},
		{
			name: "FindDefaultIDP returns an error if there are multiple IDPs configured",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithLDAP(myLDAPIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantError:              "identity provider not found: this federation domain does not have a default identity provider",
		},
		{
			name: "FindDefaultIDP returns an error if the wrapped lister does not contain the default IDP (not available)",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
					WithName("my-default-ldap-idp").
					WithResourceUID("my-ldap-idp-resource-uid-does-not-match").
					Build()).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultLDAPIDP,
			wantError:              `identity provider not available: "my-default-ldap-idp"`,
		},
	}

	for _, tt := range testFindDefaultIDP {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			foundOIDCIDP, foundLDAPIDP, err := subject.FindDefaultIDP()

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			if tt.wantDefaultOIDCIDP != nil {
				require.Equal(t, foundOIDCIDP, tt.wantDefaultOIDCIDP)
			}
			if tt.wantDefaultLDAPIDP != nil {
				require.Equal(t, foundLDAPIDP, tt.wantDefaultLDAPIDP)
			}
		})
	}

	testGetOIDCIdentityProviders := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantIDPs               []*resolvedprovider.FederationDomainResolvedOIDCIdentityProvider
	}{
		{
			name: "GetOIDCIdentityProviders will list all OIDCIdentityProviders",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{
				myOIDCIDP1Resolved,
				myOIDCIDP2Resolved,
			},
		},
		{
			name: "GetLDAPIdentityProviders will return a list of LDAP IDPs if there are LDAPIdentityProviders configured but exclude LDAP IDPs that do not have matching UIDs",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("my-oidc-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-oidc-idp-that-isnt-in-fd-issuer").
					Build()).
				WithLDAP(myLDAPIDP1).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{
				myOIDCIDP1Resolved,
				myOIDCIDP2Resolved,
			},
		},
		{
			name: "GetOIDCIdentityProviders will return nil of no OIDCIDentityProviders are found",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs:               []*resolvedprovider.FederationDomainResolvedOIDCIdentityProvider{},
		},
	}

	for _, tt := range testGetOIDCIdentityProviders {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			idps := subject.GetOIDCIdentityProviders()

			require.Equal(t, idps, tt.wantIDPs)
		})
	}

	testGetLDAPIdentityProviders := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantIDPs               []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider
	}{
		{
			name: "GetLDAPIdentityProviders will list all LDAPIdentityProviders",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
				myLDAPIDP1Resolved,
				myLDAPIDP2Resolved,
			},
		},
		{
			name: "GetLDAPIdentityProviders will return a list of LDAP IDPs if there are LDAPIdentityProviders configured but exclude LDAP IDPs that do not have matching UIDs",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
					WithName("my-ldap-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-ldap-idp-that-isnt-in-fd-issuer").
					Build()).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
				myLDAPIDP1Resolved,
			},
		},
		{
			name: "GetLDAPIdentityProviders will return an empty list of IDPs if no LDAPIdentityProviders are found",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithActiveDirectory(myADIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs:               []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{},
		},
	}
	for _, tt := range testGetLDAPIdentityProviders {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			idps := subject.GetLDAPIdentityProviders()

			require.Equal(t, idps, tt.wantIDPs)
		})
	}

	testGetActiveDirectoryIdentityProviders := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantIDPs               []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider
	}{
		{
			name: "GetActiveDirectoryIdentityProviders will return a list of LDAP IDPs if there are ActiveDirectoryIdentityProviders configured",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithActiveDirectory(myADIDP1).
				WithActiveDirectory(myADIDP2).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
				myADIDP1Resolved,
				myADIDP2Resolved,
			},
		},
		{
			name: "GetActiveDirectoryIdentityProviders will return a list of LDAP IDPs if there are ActiveDirectoryIdentityProviders configured but exclude AD IDPs that do not have matching UIDs",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithActiveDirectory(myADIDP1).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
					WithName("my-ad-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-ad-idp-that-isnt-in-fd-issuer").
					Build()).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantIDPs: []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{
				myADIDP1Resolved,
			},
		},
		{
			name: "GetActiveDirectoryIdentityProviders will return an empty list of LDAP IDPs if no ActiveDirectoryIdentityProviders are found",
			wrappedLister: oidctestutil.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADIDPs,
			wantIDPs:               []*resolvedprovider.FederationDomainResolvedLDAPIdentityProvider{},
		},
	}

	for _, tt := range testGetActiveDirectoryIdentityProviders {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			idps := subject.GetActiveDirectoryIdentityProviders()

			require.Equal(t, idps, tt.wantIDPs)
		})
	}
}
