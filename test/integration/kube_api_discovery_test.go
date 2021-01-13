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
	"k8s.io/client-go/discovery"

	"go.pinniped.dev/test/library"
)

func TestGetAPIResourceList(t *testing.T) {
	env := library.IntegrationEnv(t)

	client := library.NewKubernetesClientset(t)
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
						Verbs:      []string{"create"},
						Namespaced: true,
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
						Namespaced:   true,
						Kind:         "CredentialIssuer",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
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
						Namespaced:   true,
						Kind:         "WebhookAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
					},
					{
						Name:         "jwtauthenticators",
						SingularName: "jwtauthenticator",
						Namespaced:   true,
						Kind:         "JWTAuthenticator",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped", "pinniped-authenticator", "pinniped-authenticators"},
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
