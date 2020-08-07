/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/suzerain-io/placeholder-name/kubernetes/1.19/api/apis/placeholder/v1alpha1"
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

func addTestClusterRoleBinding(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, binding *rbacv1.ClusterRoleBinding) {
	_, err := adminClient.RbacV1().ClusterRoleBindings().Get(ctx, binding.Name, metav1.GetOptions{})
	if err != nil {
		// "404 not found" errors are acceptable, but others would be unexpected
		statusError, isStatus := err.(*errors.StatusError)
		require.True(t, isStatus)
		require.Equal(t, http.StatusNotFound, int(statusError.Status().Code))

		_, err = adminClient.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = adminClient.RbacV1().ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{})
		require.NoError(t, err, "Test failed to clean up after itself")
	})
}

func TestSuccessfulLoginRequest(t *testing.T) {
	library.SkipUnlessIntegration(t)
	tmcClusterToken := library.Getenv(t, "PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN")

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
	require.NotNil(t, response.Status.Credential.ExpirationTimestamp)
	require.InDelta(t, time.Until(response.Status.Credential.ExpirationTimestamp.Time), 1*time.Hour, float64(5*time.Second))
	require.NotNil(t, response.Status.User)
	require.NotEmpty(t, response.Status.User.Name)
	require.Contains(t, response.Status.User.Groups, "tmc:member")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewClientset(t)

	// Create a client using the certificate from the LoginRequest.
	clientWithCert := library.NewClientsetWithConfig(
		t,
		library.NewClientConfigWithCertAndKey(
			t,
			response.Status.Credential.ClientCertificateData,
			response.Status.Credential.ClientKeyData,
		),
	)

	t.Run("access as user", func(t *testing.T) {
		addTestClusterRoleBinding(ctx, t, adminClient, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: "integration-test-user-readonly-role-binding",
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
		})

		// Use the client which is authenticated as the TMC user to list namespaces
		listNamespaceResponse, err := clientWithCert.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, listNamespaceResponse.Items)
	})

	t.Run("access as group", func(t *testing.T) {
		addTestClusterRoleBinding(ctx, t, adminClient, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: "integration-test-group-readonly-role-binding",
			},
			Subjects: []rbacv1.Subject{{
				Kind:     rbacv1.GroupKind,
				APIGroup: rbacv1.GroupName,
				Name:     "tmc:member",
			}},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: rbacv1.GroupName,
				Name:     "view",
			},
		})

		// Use the client which is authenticated as the TMC group to list namespaces
		listNamespaceResponse, err := clientWithCert.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, listNamespaceResponse.Items)
	})
}

func TestFailedLoginRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser(t *testing.T) {
	library.SkipUnlessIntegration(t)
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
	library.SkipUnlessIntegration(t)
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
