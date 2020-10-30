// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestUnsuccessfulCredentialRequest(t *testing.T) {
	library.SkipUnlessIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := makeRequest(ctx, t, validCredentialRequestSpecWithRealToken(t, corev1.TypedLocalObjectReference{
		APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
		Kind:     "WebhookAuthenticator",
		Name:     "some-webhook-that-does-not-exist",
	}))
	require.NoError(t, err)
	require.Nil(t, response.Status.Credential)
	require.NotNil(t, response.Status.Message)
	require.Equal(t, "authentication failed", *response.Status.Message)
}

func TestSuccessfulCredentialRequest(t *testing.T) {
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	testWebhook := library.CreateTestWebhookAuthenticator(ctx, t)

	var response *loginv1alpha1.TokenCredentialRequest
	successfulResponse := func() bool {
		var err error
		response, err = makeRequest(ctx, t, validCredentialRequestSpecWithRealToken(t, testWebhook))
		require.NoError(t, err, "the request should never fail at the HTTP level")
		return response.Status.Credential != nil
	}
	assert.Eventually(t, successfulResponse, 10*time.Second, 500*time.Millisecond)
	require.NotNil(t, response.Status.Credential)
	require.Empty(t, response.Status.Message)
	require.Empty(t, response.Spec)
	require.Empty(t, response.Status.Credential.Token)
	require.NotEmpty(t, response.Status.Credential.ClientCertificateData)
	require.Equal(t, env.TestUser.ExpectedUsername, getCommonName(t, response.Status.Credential.ClientCertificateData))
	require.ElementsMatch(t, env.TestUser.ExpectedGroups, getOrganizations(t, response.Status.Credential.ClientCertificateData))
	require.NotEmpty(t, response.Status.Credential.ClientKeyData)
	require.NotNil(t, response.Status.Credential.ExpirationTimestamp)
	require.InDelta(t, time.Until(response.Status.Credential.ExpirationTimestamp.Time), 1*time.Hour, float64(3*time.Minute))

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
		library.AccessAsUserTest(ctx, adminClient, env.TestUser.ExpectedUsername, clientWithCertFromCredentialRequest),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group,
			library.AccessAsGroupTest(ctx, adminClient, group, clientWithCertFromCredentialRequest),
		)
	}
}

func TestFailedCredentialRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser(t *testing.T) {
	library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	response, err := makeRequest(context.Background(), t, loginv1alpha1.TokenCredentialRequestSpec{Token: "not a good token"})

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, stringPtr("authentication failed"), response.Status.Message)
}

func TestCredentialRequest_ShouldFailWhenRequestDoesNotIncludeToken(t *testing.T) {
	library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	response, err := makeRequest(context.Background(), t, loginv1alpha1.TokenCredentialRequestSpec{Token: ""})

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
	library.IntegrationEnv(t).WithoutCapability(library.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	testWebhook := library.CreateTestWebhookAuthenticator(ctx, t)

	response, err := makeRequest(ctx, t, validCredentialRequestSpecWithRealToken(t, testWebhook))

	require.NoError(t, err)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, stringPtr("authentication failed"), response.Status.Message)
}

func makeRequest(ctx context.Context, t *testing.T, spec loginv1alpha1.TokenCredentialRequestSpec) (*loginv1alpha1.TokenCredentialRequest, error) {
	t.Helper()
	env := library.IntegrationEnv(t)

	client := library.NewAnonymousPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return client.LoginV1alpha1().TokenCredentialRequests(env.ConciergeNamespace).Create(ctx, &loginv1alpha1.TokenCredentialRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{Namespace: env.ConciergeNamespace},
		Spec:       spec,
	}, metav1.CreateOptions{})
}

func validCredentialRequestSpecWithRealToken(t *testing.T, authenticator corev1.TypedLocalObjectReference) loginv1alpha1.TokenCredentialRequestSpec {
	return loginv1alpha1.TokenCredentialRequestSpec{
		Token:         library.IntegrationEnv(t).TestUser.Token,
		Authenticator: authenticator,
	}
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
