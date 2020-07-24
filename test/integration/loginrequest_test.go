/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func makeRequest(t *testing.T, spec v1alpha1.LoginRequestSpec) (*v1alpha1.LoginRequest, error) {
	t.Helper()

	client := library.NewPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return client.PlaceholderV1alpha1().LoginRequests().Create(ctx, &v1alpha1.LoginRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec:       spec,
	}, metav1.CreateOptions{})
}

func TestSuccessfulLoginRequest(t *testing.T) {
	tmcClusterToken := os.Getenv("PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN")
	require.NotEmptyf(t, tmcClusterToken, "must specify PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN env var for integration tests")

	response, err := makeRequest(t, v1alpha1.LoginRequestSpec{
		Token: &v1alpha1.LoginRequestTokenCredential{Value: tmcClusterToken},
	})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.NotEmpty(t, response.Status.Token)
	require.Empty(t, response.Status.ClientCertificateData)
	require.Empty(t, response.Status.ClientKeyData)
	require.Nil(t, response.Status.ExpirationTimestamp)
}

func TestLoginRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	_, err := makeRequest(t, v1alpha1.LoginRequestSpec{})

	require.Error(t, err)
	statusError, isStatus := err.(*errors.StatusError)
	require.True(t, isStatus)

	require.Equal(t, 1, len(statusError.ErrStatus.Details.Causes))
	cause := statusError.ErrStatus.Details.Causes[0]
	require.Equal(t, metav1.CauseType("FieldValueRequired"), cause.Type)
	require.Equal(t, "Required value: token must be supplied", cause.Message)
	require.Equal(t, "spec.token.value", cause.Field)
}

func TestGetAPIResourceList(t *testing.T) {
	client := library.NewPlaceholderNameClientset(t)

	groups, resources, err := client.Discovery().ServerGroupsAndResources()
	require.NoError(t, err)

	groupName := "placeholder.suzerain-io.github.io"
	actualGroup := findGroup(groupName, groups)
	require.NotNil(t, actualGroup)

	expectedGroup := &metav1.APIGroup{
		Name: "placeholder.suzerain-io.github.io",
		Versions: []metav1.GroupVersionForDiscovery{
			metav1.GroupVersionForDiscovery{
				GroupVersion: "placeholder.suzerain-io.github.io/v1alpha1",
				Version:      "v1alpha1",
			},
		},
		PreferredVersion: metav1.GroupVersionForDiscovery{
			GroupVersion: "placeholder.suzerain-io.github.io/v1alpha1",
			Version:      "v1alpha1",
		},
	}
	require.Equal(t, expectedGroup, actualGroup)

	resourceGroupVersion := "placeholder.suzerain-io.github.io/v1alpha1"
	actualResources := findResources(resourceGroupVersion, resources)
	require.NotNil(t, actualResources)

	expectedResources := &metav1.APIResourceList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "APIResourceList",
			APIVersion: "v1",
		},
		GroupVersion: "placeholder.suzerain-io.github.io/v1alpha1",
		APIResources: []metav1.APIResource{
			metav1.APIResource{
				Name:         "loginrequests",
				Kind:         "LoginRequest",
				SingularName: "", // TODO(akeesler): what should this be?
				Verbs: metav1.Verbs([]string{
					"create",
				}),
			},
		},
	}
	require.Equal(t, expectedResources, actualResources)
}

func TestGetAPIVersion(t *testing.T) {
	client := library.NewPlaceholderNameClientset(t)

	version, err := client.Discovery().ServerVersion()
	require.NoError(t, err)
	require.NotNil(t, version) // TODO(akeesler: what can we assert here?
}

func findGroup(name string, groups []*metav1.APIGroup) *metav1.APIGroup {
	for _, group := range groups {
		if group.Name == name {
			return group
		}
	}
	return nil
}

func findResources(groupVersion string, resources []*metav1.APIResourceList) *metav1.APIResourceList {
	for _, resource := range resources {
		if resource.GroupVersion == groupVersion {
			return resource
		}
	}
	return nil
}
