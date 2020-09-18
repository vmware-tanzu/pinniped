// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/generated/1.19/apis/login/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestSuccessfulCredentialRequest(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)
	testUsername := library.GetEnv(t, "PINNIPED_TEST_USER_USERNAME")
	expectedTestUserGroups := strings.Split(
		strings.ReplaceAll(library.GetEnv(t, "PINNIPED_TEST_USER_GROUPS"), " ", ""), ",",
	)

	response, err := makeRequest(t, validCredentialRequestSpecWithRealToken(t))
	require.NoError(t, err)

	require.NotNil(t, response.Status.Credential)
	require.Empty(t, response.Status.Message)
	require.Empty(t, response.Spec)
	require.Empty(t, response.Status.Credential.Token)
	require.NotEmpty(t, response.Status.Credential.ClientCertificateData)
	require.Equal(t, testUsername, getCommonName(t, response.Status.Credential.ClientCertificateData))
	require.ElementsMatch(t, expectedTestUserGroups, getOrganizations(t, response.Status.Credential.ClientCertificateData))
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

	t.Run(
		"access as user",
		accessAsUserTest(ctx, adminClient, testUsername, clientWithCertFromCredentialRequest),
	)
	for _, group := range expectedTestUserGroups {
		group := group
		t.Run(
			"access as group "+group,
			accessAsGroupTest(ctx, adminClient, group, clientWithCertFromCredentialRequest),
		)
	}
}

func TestFailedCredentialRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)

	response, err := makeRequest(t, v1alpha1.TokenCredentialRequestSpec{Token: "not a good token"})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, stringPtr("authentication failed"), response.Status.Message)
}

func TestCredentialRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)

	response, err := makeRequest(t, v1alpha1.TokenCredentialRequestSpec{Token: ""})

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

func TestCredentialRequest_OtherwiseValidRequestWithRealTokenShouldFailWhenTheClusterIsNotCapable(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipWhenClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)

	response, err := makeRequest(t, validCredentialRequestSpecWithRealToken(t))

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, stringPtr("authentication failed"), response.Status.Message)
}

func makeRequest(t *testing.T, spec v1alpha1.TokenCredentialRequestSpec) (*v1alpha1.TokenCredentialRequest, error) {
	t.Helper()

	client := library.NewAnonymousPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ns := library.GetEnv(t, "PINNIPED_NAMESPACE")
	return client.LoginV1alpha1().TokenCredentialRequests(ns).Create(ctx, &v1alpha1.TokenCredentialRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec:       spec,
	}, metav1.CreateOptions{})
}

func validCredentialRequestSpecWithRealToken(t *testing.T) v1alpha1.TokenCredentialRequestSpec {
	return v1alpha1.TokenCredentialRequestSpec{Token: library.GetEnv(t, "PINNIPED_TEST_USER_TOKEN")}
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

func getOrganizations(t *testing.T, certPEM string) []string {
	t.Helper()

	pemBlock, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert.Subject.Organization
}
