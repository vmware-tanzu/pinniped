/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/pinniped/test/library"
)

func TestGetAPIResourceList(t *testing.T) {
	library.SkipUnlessIntegration(t)

	client := library.NewPinnipedClientset(t)

	groups, resources, err := client.Discovery().ServerGroupsAndResources()
	require.NoError(t, err)

	t.Run("has group", func(t *testing.T) {
		require.Contains(t, groups, &metav1.APIGroup{
			Name: "pinniped.dev",
			Versions: []metav1.GroupVersionForDiscovery{
				{
					GroupVersion: "pinniped.dev/v1alpha1",
					Version:      "v1alpha1",
				},
			},
			PreferredVersion: metav1.GroupVersionForDiscovery{
				GroupVersion: "pinniped.dev/v1alpha1",
				Version:      "v1alpha1",
			},
		})
	})

	t.Run("has non-CRD APIs", func(t *testing.T) {
		expectResources(t, "pinniped.dev/v1alpha1", resources, []metav1.APIResource{
			{
				Name:       "credentialrequests",
				Kind:       "CredentialRequest",
				Verbs:      []string{"create"},
				Namespaced: false,

				// This is currently an empty string in the response; maybe it should not be
				// empty? Seems like no harm in keeping it like this for now, but feel free
				// to update in the future if there is a compelling reason to do so.
				SingularName: "",
			},
		})
	})

	t.Run("has CRD APIs", func(t *testing.T) {
		expectResources(t, "crd.pinniped.dev/v1alpha1", resources, []metav1.APIResource{
			{
				Name:         "credentialissuerconfigs",
				SingularName: "credentialissuerconfig",
				Namespaced:   true,
				Kind:         "CredentialIssuerConfig",
				Verbs:        []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
				ShortNames:   []string{"cic"},
			},
		})
	})
}

func expectResources(t *testing.T, groupVersion string, resources []*metav1.APIResourceList, expected []metav1.APIResource) {
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
	require.EqualValues(t, expected, actualResourceList.APIResources, "unexpected API resources")
}
