// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/test/library"
)

func TestGetAPIResourceList(t *testing.T) {
	library.SkipUnlessIntegration(t)

	client := library.NewPinnipedClientset(t)

	groups, resources, err := client.Discovery().ServerGroupsAndResources()
	require.NoError(t, err)

	tests := []struct {
		group             metav1.APIGroup
		resourceByVersion map[string][]metav1.APIResource
	}{
		{
			group: metav1.APIGroup{
				Name: "login.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "login.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "login.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"login.pinniped.dev/v1alpha1": {
					{
						Name:       "tokencredentialrequests",
						Kind:       "TokenCredentialRequest",
						Verbs:      []string{"create"},
						Namespaced: true,

						// This is currently an empty string in the response; maybe it should not be
						// empty? Seems like no harm in keeping it like this for now, but feel free
						// to update in the future if there is a compelling reason to do so.
						SingularName: "",
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: "config.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "config.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "config.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"config.pinniped.dev/v1alpha1": {
					{
						Name:         "credentialissuerconfigs",
						SingularName: "credentialissuerconfig",
						Namespaced:   true,
						Kind:         "CredentialIssuerConfig",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						ShortNames:   []string{"cic"},
					},
				},
			},
		},
		{
			group: metav1.APIGroup{
				Name: "idp.pinniped.dev",
				Versions: []metav1.GroupVersionForDiscovery{
					{
						GroupVersion: "idp.pinniped.dev/v1alpha1",
						Version:      "v1alpha1",
					},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{
					GroupVersion: "idp.pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			resourceByVersion: map[string][]metav1.APIResource{
				"idp.pinniped.dev/v1alpha1": {
					{
						Name:         "webhookidentityproviders",
						SingularName: "webhookidentityprovider",
						Namespaced:   true,
						Kind:         "WebhookIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						ShortNames:   []string{"webhookidp", "webhookidps"},
						Categories:   []string{"all", "idp", "idps"},
					},
					{
						Name:         "openidconnectidentityproviders",
						SingularName: "openidconnectidentityprovider",
						Namespaced:   true,
						Kind:         "OpenIDConnectIdentityProvider",
						Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
						ShortNames:   []string{"openidconnectidp", "openidconnectidps"},
						Categories:   []string{"all", "idp", "idps"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.group.Name, func(t *testing.T) {
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
