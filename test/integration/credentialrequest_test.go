/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/suzerain-io/placeholder-name/kubernetes/1.19/api/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/test/library"
)

func makeRequest(t *testing.T, spec v1alpha1.CredentialRequestSpec) (*v1alpha1.CredentialRequest, error) {
	t.Helper()

	client := library.NewAnonymousPlaceholderNameClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return client.PlaceholderV1alpha1().CredentialRequests().Create(ctx, &v1alpha1.CredentialRequest{
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

func TestSuccessfulCredentialRequest(t *testing.T) {
	library.SkipUnlessIntegration(t)
	tmcClusterToken := library.Getenv(t, "PLACEHOLDER_NAME_TMC_CLUSTER_TOKEN")

	response, err := makeRequest(t, v1alpha1.CredentialRequestSpec{
		Type:  v1alpha1.TokenCredentialType,
		Token: &v1alpha1.CredentialRequestTokenCredential{Value: tmcClusterToken},
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
	require.InDelta(t, time.Until(response.Status.Credential.ExpirationTimestamp.Time), 1*time.Hour, float64(3*time.Minute))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewClientset(t)

	// Create a client using the certificate from the CredentialRequest.
	clientWithCertFromCredentialRequest := library.NewClientsetWithCertAndKey(
		t,
		response.Status.Credential.ClientCertificateData,
		response.Status.Credential.ClientKeyData,
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
				Name:     getCommonName(t, response.Status.Credential.ClientCertificateData),
			}},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: rbacv1.GroupName,
				Name:     "view",
			},
		})

		// Use the client which is authenticated as the TMC user to list namespaces
		var listNamespaceResponse *v1.NamespaceList
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientWithCertFromCredentialRequest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, 3*time.Second, 250*time.Millisecond)
		require.NoError(t, err) // prints out the error in case of failure
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
		var listNamespaceResponse *v1.NamespaceList
		var canListNamespaces = func() bool {
			listNamespaceResponse, err = clientWithCertFromCredentialRequest.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			return err == nil
		}
		assert.Eventually(t, canListNamespaces, 3*time.Second, 250*time.Millisecond)
		require.NoError(t, err) // prints out the error in case of failure
		require.NotEmpty(t, listNamespaceResponse.Items)
	})
}

func TestFailedCredentialRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser(t *testing.T) {
	library.SkipUnlessIntegration(t)
	response, err := makeRequest(t, v1alpha1.CredentialRequestSpec{
		Type:  v1alpha1.TokenCredentialType,
		Token: &v1alpha1.CredentialRequestTokenCredential{Value: "not a good token"},
	})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, stringPtr("authentication failed"), response.Status.Message)
}

func TestCredentialRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	library.SkipUnlessIntegration(t)
	response, err := makeRequest(t, v1alpha1.CredentialRequestSpec{
		Type:  v1alpha1.TokenCredentialType,
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

func stringPtr(s string) *string {
	return &s
}

func getCommonName(t *testing.T, certPEM string) string {
	t.Helper()

	pemBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert.Subject.CommonName
}
