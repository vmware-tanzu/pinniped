// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/discovery"

	"go.pinniped.dev/test/testlib"
)

func TestGetAPIResourceList(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	client := testlib.NewKubernetesClientset(t)
	groups, resources, err := client.Discovery().ServerGroupsAndResources()

	// discovery can have partial failures when an API service is unavailable (i.e. because of TestAPIServingCertificateAutoCreationAndRotation)
	// we ignore failures for groups that are not relevant to this test
	if err != nil {
		discoveryFailed := &discovery.ErrGroupDiscoveryFailed{}
		isDiscoveryFailed := errors.As(err, &discoveryFailed)
		require.True(t, isDiscoveryFailed, err)
		for gv, gvErr := range discoveryFailed.Groups {
			if strings.HasSuffix(gv.Group, "."+env.APIGroupSuffix) {
				require.NoError(t, gvErr)
			}
		}
	}

	makeGV := func(firstSegment, secondSegment string) schema.GroupVersion {
		return schema.GroupVersion{
			Group:   fmt.Sprintf("%s.%s.%s", firstSegment, secondSegment, env.APIGroupSuffix),
			Version: "v1alpha1",
		}
	}
	loginConciergeGV := makeGV("login", "concierge")
	identityConciergeGV := makeGV("identity", "concierge")
	authenticationConciergeGV := makeGV("authentication", "concierge")
	configConciergeGV := makeGV("config", "concierge")
	idpSupervisorGV := makeGV("idp", "supervisor")
	configSupervisorGV := makeGV("config", "supervisor")

	tests := []struct {
		group             metav1.APIGroup
		resourceByVersion map[string][]metav1.APIResource
	}{
		{
			group: metav1.APIGroup{
				Name: loginConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: loginConciergeGV.String(),
						Version:      loginConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: loginConciergeGV.String(),
					Version:      loginConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				loginConciergeGV.String(): {
					{
						Name:       "tokencredentialrequests",
						Kind:       "TokenCredentialRequest",
						Verbs:      []string{"create", "list"},
						Namespaced: false,
						Categories: []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: identityConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: identityConciergeGV.String(),
						Version:      identityConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: identityConciergeGV.String(),
					Version:      identityConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				identityConciergeGV.String(): {
					{
						Name:       "whoamirequests",
						Kind:       "WhoAmIRequest",
						Verbs:      []string{"create", "list"},
						Namespaced: false,
						Categories: []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: configSupervisorGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: configSupervisorGV.String(),
						Version:      configSupervisorGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: configSupervisorGV.String(),
					Version:      configSupervisorGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				configSupervisorGV.String(): {
					{
						Name:         "federationdomains",
						SingularName: "federationdomain",
						Namespaced:   true,
						Kind:         "FederationDomain",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
					{
						Name:       "federationdomains/status",
						Namespaced: true,
						Kind:       "FederationDomain",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: idpSupervisorGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: idpSupervisorGV.String(),
						Version:      idpSupervisorGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: idpSupervisorGV.String(),
					Version:      idpSupervisorGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				idpSupervisorGV.String(): {
					{
						Name:         "oidcidentityproviders",
						SingularName: "oidcidentityprovider",
						Namespaced:   true,
						Kind:         "OIDCIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "oidcidentityproviders/status",
						Namespaced: true,
						Kind:       "OIDCIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "ldapidentityproviders",
						SingularName: "ldapidentityprovider",
						Namespaced:   true,
						Kind:         "LDAPIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "ldapidentityproviders/status",
						Namespaced: true,
						Kind:       "LDAPIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "activedirectoryidentityproviders",
						SingularName: "activedirectoryidentityprovider",
						Namespaced:   true,
						Kind:         "ActiveDirectoryIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-idp", "pinniped-idps"},
					},
					{
						Name:       "activedirectoryidentityproviders/status",
						Namespaced: true,
						Kind:       "ActiveDirectoryIdentityProvider",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: configConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: configConciergeGV.String(),
						Version:      configConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: configConciergeGV.String(),
					Version:      configConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				configConciergeGV.String(): {
					{
						Name:         "credentialissuers",
						SingularName: "credentialissuer",
						Namespaced:   false,
						Kind:         "CredentialIssuer",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
					{
						Name:       "credentialissuers/status",
						Namespaced: false,
						Kind:       "CredentialIssuer",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: authenticationConciergeGV.Group,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: authenticationConciergeGV.String(),
						Version:      authenticationConciergeGV.Version,
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: authenticationConciergeGV.String(),
					Version:      authenticationConciergeGV.Version,
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				authenticationConciergeGV.String(): {
					{
						Name:         "webhookauthenticators",
						SingularName: "webhookauthenticator",
						Namespaced:   false,
						Kind:         "WebhookAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
					},
					{
						Name:       "webhookauthenticators/status",
						Namespaced: false,
						Kind:       "WebhookAuthenticator",
						Verbs:      []string{"get", "patch", "update"},
					},
					{
						Name:         "jwtauthenticators",
						SingularName: "jwtauthenticator",
						Namespaced:   false,
						Kind:         "JWTAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
					},
					{
						Name:       "jwtauthenticators/status",
						Namespaced: false,
						Kind:       "JWTAuthenticator",
						Verbs:      []string{"get", "patch", "update"},
					},
				},
			},
		},
	}

	t.Run("every Pinniped API has explicit test coverage", func(t *testing.T) {
		t.Parallel()
		testedGroups := map[string]bool{}
		for _, tt := range tests {
			testedGroups[tt.group.Name] = true
		}
		foundPinnipedGroups := 0
		for _, g := range groups {
			if !strings.Contains(g.Name, env.APIGroupSuffix) {
				continue
			}
			foundPinnipedGroups++
			assert.Truef(t, testedGroups[g.Name], "expected group %q to have assertions defined", g.Name)
		}
		require.Equal(t, len(testedGroups), foundPinnipedGroups)
	})

	t.Run("every API categorized appropriately", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}
			for _, a := range r.APIResources {
				if strings.HasSuffix(a.Name, "/status") {
					continue
				}
				assert.Containsf(t, a.Categories, "pinniped", "expected resource %q to be in the 'pinniped' category", a.Name)
				assert.NotContainsf(t, a.Categories, "all", "expected resource %q not to be in the 'all' category", a.Name)
			}
		}
	})

	t.Run("every concierge API is cluster scoped", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}

			if !strings.Contains(r.GroupVersion, ".concierge.") {
				continue
			}

			for _, a := range r.APIResources {
				assert.False(t, a.Namespaced, "concierge APIs must be cluster scoped: %#v", a)
			}
		}
	})

	t.Run("every API has a status subresource", func(t *testing.T) {
		t.Parallel()

		aggregatedAPIs := sets.NewString("tokencredentialrequests", "whoamirequests")

		var regular, status []string

		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}

			for _, a := range r.APIResources {
				if aggregatedAPIs.Has(a.Name) {
					continue // skip our special aggregated APIs with their own magical properties
				}

				if strings.HasSuffix(a.Name, "/status") {
					status = append(status, strings.TrimSuffix(a.Name, "/status"))
				} else {
					regular = append(regular, a.Name)
				}
			}
		}

		assert.Equal(t, regular, status)
	})

	t.Run("Pinniped resources do not have short names", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, env.APIGroupSuffix) {
				continue
			}
			for _, a := range r.APIResources {
				assert.Empty(t, a.ShortNames, "expected resource %q not to have any short names", a.Name)
			}
		}
	})

	for _, tt := range tests {
		tt := tt
		t.Run(tt.group.Name, func(t *testing.T) {
			t.Parallel()
			require.Contains(t, groups, &tt.group)

			for groupVersion, expectedResources := range tt.resourceByVersion {
				// Find the actual resource list and make a copy.
				var actualResourceList *metav1.APIResourceList
				for _, resource := range resources {
					if resource.GroupVersion == groupVersion {
						actualResourceList = resource.DeepCopy()
					}
				}
				require.NotNilf(t, actualResourceList, "could not find groupVersion %s", groupVersion)

				// Because its hard to predict the storage version hash (e.g. "t/+v41y+3e4="), we just don't
				// worry about comparing that field.
				for i := range actualResourceList.APIResources {
					actualResourceList.APIResources[i].StorageVersionHash = ""
				}
				require.ElementsMatch(t, expectedResources, actualResourceList.APIResources, "unexpected API resources")
			}
		})
	}
}
