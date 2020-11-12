// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/test/library"
)

func TestGetAPIResourceList(t *testing.T) {
	library.SkipUnlessIntegration(t)

	client := library.NewConciergeClientset(t)

	groups, resources, err := client.Discovery().ServerGroupsAndResources()
	require.NoError(t, err)

	tests := []struct {
		group             metav1.APIGroup
		resourceByVersion map[string][]metav1.APIResource
	}{
		{
			group: metav1.APIGroup{
				Name: "login.concierge.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "login.concierge.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "login.concierge.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"login.concierge.pinniped.dev/v1alpha1": {
					{
						Name:       "tokencredentialrequests",
						Kind:       "TokenCredentialRequest",
						Verbs:      []string{"create"},
						Namespaced: true,
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: "config.supervisor.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "config.supervisor.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "config.supervisor.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"config.supervisor.pinniped.dev/v1alpha1": {
					{
						Name:         "oidcproviders",
						SingularName: "oidcprovider",
						Namespaced:   true,
						Kind:         "OIDCProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						Categories:   []string{"pinniped"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: "config.concierge.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "config.concierge.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "config.concierge.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"config.concierge.pinniped.dev/v1alpha1": {
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
				Name: "authentication.concierge.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "authentication.concierge.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "authentication.concierge.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"authentication.concierge.pinniped.dev/v1alpha1": {
					{
						Name:         "webhookauthenticators",
						SingularName: "webhookauthenticator",
						Namespaced:   true,
						Kind:         "WebhookAuthenticator",
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
		for _, g := range groups {
			if !strings.Contains(g.Name, "pinniped.dev") {
				continue
			}
			assert.Truef(t, testedGroups[g.Name], "expected group %q to have assertions defined", g.Name)
		}
	})

	t.Run("every API categorized appropriately", func(t *testing.T) {
		t.Parallel()
		for _, r := range resources {
			if !strings.Contains(r.GroupVersion, "pinniped.dev") {
				continue
			}
			for _, a := range r.APIResources {
				if a.Kind != "TokenCredentialRequest" {
					assert.Containsf(t, a.Categories, "pinniped", "expected resource %q to be in the 'pinniped' category", a.Name)
				}
				assert.NotContainsf(t, a.Categories, "all", "expected resource %q not to be in the 'all' category", a.Name)
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
