/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
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
		Type:  v1alpha1.TokenLoginCredentialType,
		Token: &v1alpha1.LoginRequestTokenCredential{Value: tmcClusterToken},
	})

	require.NoError(t, err)

	// Note: If this assertion fails then your TMC token might have expired. Get a fresh one and try again.
	require.Empty(t, response.Status.Message)

	require.Empty(t, response.Spec)
	require.NotNil(t, response.Status.Credential)
	require.Empty(t, response.Status.Credential.Token)
	require.NotEmpty(t, response.Status.Credential.ClientCertificateData)
	require.NotEmpty(t, response.Status.Credential.ClientKeyData)
	require.Nil(t, response.Status.Credential.ExpirationTimestamp)
	require.NotNil(t, response.Status.User)
	require.NotEmpty(t, response.Status.User.Name)
	require.Contains(t, response.Status.User.Groups, "tmc:member")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const readonlyBindingName = "integration-test-user-readonly-role-binding"

	adminClient := library.NewClientset(t)
	_, err = adminClient.RbacV1().ClusterRoleBindings().Get(ctx, readonlyBindingName, metav1.GetOptions{})
	if err != nil {
		// "404 not found" errors are acceptable, but others would be unexpected
		statusError, isStatus := err.(*errors.StatusError)
		require.True(t, isStatus)
		require.Equal(t, http.StatusNotFound, int(statusError.Status().Code))

		// Create a ClusterRoleBinding for this user only if one is not already found (so you can run tests more than once)
		bindUserToReadonly := rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: readonlyBindingName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:     rbacv1.UserKind,
				APIGroup: rbacv1.GroupName,
				Name:     response.Status.User.Name,
			}},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: rbacv1.GroupName,
				Name:     "view",
			},
		}
		_, err = adminClient.RbacV1().ClusterRoleBindings().Create(ctx, &bindUserToReadonly, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = adminClient.RbacV1().ClusterRoleBindings().Delete(ctx, readonlyBindingName, metav1.DeleteOptions{})
		require.NoError(t, err, "Test failed to clean up after itself")
	}()

	// Create a client using the certificate from the LoginRequest
	clientWithCert := library.NewClientsetWithConfig(
		t,
		library.NewClientConfigWithCertAndKey(
			t,
			response.Status.Credential.ClientCertificateData,
			response.Status.Credential.ClientKeyData,
		),
	)

	// Use the client which is authenticated as the TMC user to list namespaces
	listNamespaceResponse, err := clientWithCert.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, listNamespaceResponse.Items)
}

func TestFailedLoginRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser(t *testing.T) {
	response, err := makeRequest(t, v1alpha1.LoginRequestSpec{
		Type:  v1alpha1.TokenLoginCredentialType,
		Token: &v1alpha1.LoginRequestTokenCredential{Value: "not a good token"},
	})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Nil(t, response.Status.User)
	require.Equal(t, "authentication failed", response.Status.Message)
}

func TestLoginRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	response, err := makeRequest(t, v1alpha1.LoginRequestSpec{
		Type:  v1alpha1.TokenLoginCredentialType,
		Token: nil,
	})

	require.Error(t, err)
	statusError, isStatus := err.(*errors.StatusError)
	require.True(t, isStatus)

	require.Equal(t, 1, len(statusError.ErrStatus.Details.Causes))
	cause := statusError.ErrStatus.Details.Causes[0]
	require.Equal(t, metav1.CauseType("FieldValueRequired"), cause.Type)
	require.Equal(t, "Required value: token must be supplied", cause.Message)
	require.Equal(t, "spec.token.value", cause.Field)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
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
			{
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
			{
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
	require.NotNil(t, version) // TODO(akeesler): what can we assert here?
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
