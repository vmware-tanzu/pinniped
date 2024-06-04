// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package federationdomainproviders

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/idplister"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedgithub"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedldap"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedoidc"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
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
	myDefaultGitHubIDP := oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
		WithName("my-default-github-idp").
		WithResourceUID("my-default-github-uid-idp").
		Build()
	myGitHubIDP1 := oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
		WithName("my-github-idp1").
		WithResourceUID("my-github-uid-idp1").
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

	fdIssuerWithDefaultGitHubIDP, err := NewFederationDomainIssuerWithDefaultIDP(fakeIssuerURL, &FederationDomainIdentityProvider{
		DisplayName: "my-default-github-idp",
		UID:         "my-default-github-uid-idp",
	})
	require.NoError(t, err)

	fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-oidc-idp1", UID: "my-oidc-uid-idp1"},
		{DisplayName: "my-oidc-idp2", UID: "my-oidc-uid-idp2"},
		{DisplayName: "my-ldap-idp1", UID: "my-ldap-uid-idp1"},
		{DisplayName: "my-ldap-idp2", UID: "my-ldap-uid-idp2"},
		{DisplayName: "my-ad-idp1", UID: "my-ad-uid-idp1"},
		{DisplayName: "my-ad-idp2", UID: "my-ad-uid-idp2"},
		{DisplayName: "my-github-idp1", UID: "my-github-uid-idp1"},
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
		{DisplayName: "my-github-idp1", UID: "my-github-uid-idp1"},
	})
	require.NoError(t, err)

	fdIssuerWithIDPWithLostUID, err := NewFederationDomainIssuer(fakeIssuerURL, []*FederationDomainIdentityProvider{
		{DisplayName: "my-idp", UID: "you-cant-find-my-uid"},
	})
	require.NoError(t, err)

	// Resolved IdPs
	myOIDCIDP1Resolved := &resolvedoidc.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-oidc-idp1",
		Provider:            myOIDCIDP1,
		SessionProviderType: "oidc",
	}
	myOIDCIDP2Resolved := &resolvedoidc.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-oidc-idp2",
		Provider:            myOIDCIDP2,
		SessionProviderType: "oidc",
	}
	myLDAPIDP1Resolved := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ldap-idp1",
		Provider:            myLDAPIDP1,
		SessionProviderType: "ldap",
	}
	myLDAPIDP2Resolved := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ldap-idp2",
		Provider:            myLDAPIDP2,
		SessionProviderType: "ldap",
	}
	myADIDP1Resolved := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-ad-idp1",
		Provider:            myADIDP1,
		SessionProviderType: "activedirectory",
	}
	myGitHub1Resolved := &resolvedgithub.FederationDomainResolvedGitHubIdentityProvider{
		DisplayName:         "my-github-idp1",
		Provider:            myGitHubIDP1,
		SessionProviderType: "github",
	}

	myDefaultOIDCIDPResolved := &resolvedoidc.FederationDomainResolvedOIDCIdentityProvider{
		DisplayName:         "my-default-oidc-idp",
		Provider:            myDefaultOIDCIDP,
		SessionProviderType: "oidc",
	}
	myDefaultLDAPIDPResolved := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
		DisplayName:         "my-default-ldap-idp",
		Provider:            myDefaultLDAPIDP,
		SessionProviderType: "ldap",
	}
	myDefaultGitHubIDPResolved := &resolvedgithub.FederationDomainResolvedGitHubIdentityProvider{
		DisplayName:         "my-default-github-idp",
		Provider:            myDefaultGitHubIDP,
		SessionProviderType: "github",
	}

	testFindUpstreamIDPByDisplayName := []struct {
		name                       string
		wrappedLister              idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer     *FederationDomainIssuer
		findIDPByDisplayName       string
		wantOIDCIDPByDisplayName   *resolvedoidc.FederationDomainResolvedOIDCIdentityProvider
		wantLDAPIDPByDisplayName   *resolvedldap.FederationDomainResolvedLDAPIdentityProvider
		wantGitHubIDPByDisplayName *resolvedgithub.FederationDomainResolvedGitHubIdentityProvider
		wantError                  string
	}{
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IdP by display name with one IDP configured",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithLDAP(myLDAPIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP1,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP by display name if multiple IDPs configured of the same type",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP2,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP by display name if multiple IDPs configured of different types",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type OIDC by display name",
			findIDPByDisplayName: "my-oidc-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCIDP1,
			wantOIDCIDPByDisplayName: myOIDCIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type LDAP by display name",
			findIDPByDisplayName: "my-ldap-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantLDAPIDPByDisplayName: myLDAPIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type AD (LDAP) by display name",
			findIDPByDisplayName: "my-ad-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:   fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantLDAPIDPByDisplayName: myADIDP1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will find an upstream IDP of type GitHub by display name",
			findIDPByDisplayName: "my-github-idp1",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer:     fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantGitHubIDPByDisplayName: myGitHub1Resolved,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will error if IDP by display name is not found - no such display name",
			findIDPByDisplayName: "i-cant-find-my-idp",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantError:              `identity provider not found: "i-cant-find-my-idp"`,
		},
		{
			name:                 "FindUpstreamIDPByDisplayName will error if IDP by display name is not found - display name was found, but IDP it points at does not exist",
			findIDPByDisplayName: "my-idp",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithIDPWithLostUID,
			wantError:              `identity provider not available: "my-idp"`,
		},
	}

	for _, tt := range testFindUpstreamIDPByDisplayName {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			foundIDP, err := subject.FindUpstreamIDPByDisplayName(tt.findIDPByDisplayName)

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			if tt.wantOIDCIDPByDisplayName != nil {
				require.Equal(t, tt.wantOIDCIDPByDisplayName, foundIDP)
			}
			if tt.wantLDAPIDPByDisplayName != nil {
				require.Equal(t, tt.wantLDAPIDPByDisplayName, foundIDP)
			}
			if tt.wantGitHubIDPByDisplayName != nil {
				require.Equal(t, tt.wantGitHubIDPByDisplayName, foundIDP)
			}
		})
	}

	testFindDefaultIDP := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantDefaultOIDCIDP     *resolvedoidc.FederationDomainResolvedOIDCIdentityProvider
		wantDefaultLDAPIDP     *resolvedldap.FederationDomainResolvedLDAPIdentityProvider
		wantDefaultGitHubIDP   *resolvedgithub.FederationDomainResolvedGitHubIdentityProvider
		wantError              string
	}{
		{
			name: "FindDefaultIDP returns an OIDCIdentityProvider if there is an OIDCIdentityProvider defined as the default IDP",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myDefaultOIDCIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultOIDCIDP,
			wantDefaultOIDCIDP:     myDefaultOIDCIDPResolved,
		},
		{
			name: "FindDefaultIDP returns an LDAPIdentityProvider if there is an LDAPIdentityProvider defined as the default IDP",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(myDefaultLDAPIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultLDAPIDP,
			wantDefaultLDAPIDP:     myDefaultLDAPIDPResolved,
		},
		{
			name: "FindDefaultIDP resturns a GitHubIdentityProvider if there is a GitHubIdentityProvider defined as the default IDP",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithGitHub(myDefaultGitHubIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultGitHubIDP,
			wantDefaultGitHubIDP:   myDefaultGitHubIDPResolved,
		},
		{
			name: "FindDefaultIDP returns an error if there is no default IDP to return",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(myDefaultLDAPIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithoutIDP,
			wantError:              "identity provider not found: this federation domain does not have a default identity provider",
		},
		{
			name: "FindDefaultIDP returns an error if there are multiple IDPs configured",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithLDAP(myLDAPIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantError:              "identity provider not found: this federation domain does not have a default identity provider",
		},
		{
			name: "FindDefaultIDP returns an error if the wrapped lister does not contain the default IDP (not available)",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			foundIDP, err := subject.FindDefaultIDP()

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
			if tt.wantDefaultOIDCIDP != nil {
				require.Equal(t, tt.wantDefaultOIDCIDP, foundIDP)
			}
			if tt.wantDefaultLDAPIDP != nil {
				require.Equal(t, tt.wantDefaultLDAPIDP, foundIDP)
			}
			if tt.wantDefaultGitHubIDP != nil {
				require.Equal(t, tt.wantDefaultGitHubIDP, foundIDP)
			}
		})
	}

	testGetIdentityProviders := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantIDPs               []resolvedprovider.FederationDomainResolvedIdentityProvider
	}{
		{
			name: "GetIdentityProviders will list all identity providers that can be resolved",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithLDAP(myLDAPIDP1).
				WithLDAP(myLDAPIDP2).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantIDPs: []resolvedprovider.FederationDomainResolvedIdentityProvider{
				myOIDCIDP1Resolved,
				myOIDCIDP2Resolved,
				myLDAPIDP1Resolved,
				myLDAPIDP2Resolved,
				myADIDP1Resolved,
				myGitHub1Resolved,
			},
		},
		{
			name: "GetIdentityProviders will return a list of IDPs if there are IDPs configured but exclude IDPs that do not have matching UIDs",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("my-oidc-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-oidc-idp-that-isnt-in-fd-issuer").
					Build()).
				WithLDAP(myLDAPIDP1).
				WithActiveDirectory(myADIDP1).
				WithGitHub(myGitHubIDP1).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithLotsOfIDPs,
			wantIDPs: []resolvedprovider.FederationDomainResolvedIdentityProvider{
				myOIDCIDP1Resolved,
				myOIDCIDP2Resolved,
				myLDAPIDP1Resolved,
				myADIDP1Resolved,
				myGitHub1Resolved,
			},
		},
		{
			name: "GetIdentityProviders will return empty list if no IDPs are found",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantIDPs:               []resolvedprovider.FederationDomainResolvedIdentityProvider{},
		},
	}

	for _, tt := range testGetIdentityProviders {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)
			idps := subject.GetIdentityProviders()

			require.Equal(t, tt.wantIDPs, idps)
		})
	}

	testIDPCount := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantCount              int
	}{
		{
			name: "IDPCount when there are none to be found",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantCount:              0,
		},
		{
			name: "IDPCount when there are various types of IDP to be found",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myOIDCIDP1).
				WithOIDC(myOIDCIDP2).
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("my-oidc-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-oidc-idp-that-isnt-in-fd-issuer").
					Build()).
				WithLDAP(myLDAPIDP1).
				WithLDAP(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
					WithName("my-ldap-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-ldap-idp-that-isnt-in-fd-issuer").
					Build()).
				WithActiveDirectory(myADIDP1).
				WithActiveDirectory(myADIDP2).
				WithActiveDirectory(oidctestutil.NewTestUpstreamLDAPIdentityProviderBuilder().
					WithName("my-ad-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-ad-idp-that-isnt-in-fd-issuer").
					Build()).
				WithGitHub(myGitHubIDP1).
				WithGitHub(oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
					WithName("my-github-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-github-idp-that-isnt-in-fd-issuer").
					Build()).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantCount:              6,
		},
	}

	for _, tt := range testIDPCount {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)

			require.Equal(t, tt.wantCount, subject.IDPCount())
		})
	}

	testHasDefaultIDP := []struct {
		name                   string
		wrappedLister          idplister.UpstreamIdentityProvidersLister
		federationDomainIssuer *FederationDomainIssuer
		wantHasDefaultIDP      bool
	}{
		{
			name: "HasDefaultIDP when there is an OIDC provider set as default",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(myDefaultOIDCIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultOIDCIDP,
			wantHasDefaultIDP:      true,
		},
		{
			name: "HasDefaultIDP when there is an LDAP provider set as default",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithLDAP(myDefaultLDAPIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultLDAPIDP,
			wantHasDefaultIDP:      true,
		},
		{
			name: "HasDefaultIDP when there is a GitHub provider set as default",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithGitHub(myDefaultGitHubIDP).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultGitHubIDP,
			wantHasDefaultIDP:      true,
		},
		{
			name: "HasDefaultIDP when there is one set even if it cannot be found",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				WithOIDC(oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("my-oidc-idp-that-isnt-in-fd-issuer").
					WithResourceUID("my-oidc-idp-that-isnt-in-fd-issuer").
					Build()).
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithDefaultOIDCIDP,
			wantHasDefaultIDP:      true,
		},
		{
			name: "HasDefaultIDP when there is none set",
			wrappedLister: testidplister.NewUpstreamIDPListerBuilder().
				BuildDynamicUpstreamIDPProvider(),
			federationDomainIssuer: fdIssuerWithOIDCAndLDAPAndADAndGitHubIDPs,
			wantHasDefaultIDP:      false,
		},
	}

	for _, tt := range testHasDefaultIDP {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := NewFederationDomainIdentityProvidersListerFinder(tt.federationDomainIssuer, tt.wrappedLister)

			require.Equal(t, tt.wantHasDefaultIDP, subject.HasDefaultIDP())
		})
	}
}
