// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestUnsuccessfulCredentialRequest_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	response, err := testlib.CreateTokenCredentialRequest(ctx, t,
		loginv1alpha1.TokenCredentialRequestSpec{
			Token: env.TestUser.Token,
			Authenticator: corev1.TypedLocalObjectReference{
				APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
				Kind:     "WebhookAuthenticator",
				Name:     "some-webhook-that-does-not-exist",
			},
		},
	)
	require.NoError(t, err, testlib.Sdump(err))
	require.Nil(t, response.Status.Credential)
	require.NotNil(t, response.Status.Message)
	require.Equal(t, "authentication failed", *response.Status.Message)
}

// TestSuccessfulCredentialRequest_Browser cannot run in parallel because runPinnipedLoginOIDC uses a fixed port
// for its localhost listener via --listen-port=env.CLIUpstreamOIDC.CallbackURL.Port() per oidcLoginCommand.
// Since ports are global to the process, tests using oidcLoginCommand must be run serially.
func TestSuccessfulCredentialRequest_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	tests := []struct {
		name          string
		authenticator func(context.Context, *testing.T) corev1.TypedLocalObjectReference
		token         func(t *testing.T) (token string, username string, groups []string)
	}{
		{
			name: "webhook",
			authenticator: func(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
				return testlib.CreateTestWebhookAuthenticator(ctx, t, &testlib.IntegrationEnv(t).TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)
			},
			token: func(t *testing.T) (string, string, []string) {
				return testlib.IntegrationEnv(t).TestUser.Token, env.TestUser.ExpectedUsername, env.TestUser.ExpectedGroups
			},
		},
		{
			name: "jwt authenticator",
			authenticator: func(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
				authenticator := testlib.CreateTestJWTAuthenticatorForCLIUpstream(ctx, t)
				return corev1.TypedLocalObjectReference{
					APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
					Kind:     "JWTAuthenticator",
					Name:     authenticator.Name,
				}
			},
			token: func(t *testing.T) (string, string, []string) {
				pinnipedExe := testlib.PinnipedCLIPath(t)
				credOutput, _ := runPinnipedLoginOIDC(ctx, t, pinnipedExe)
				token := credOutput.Status.Token

				// By default, the JWTAuthenticator expects the username to be in the "username" claim and the
				// groups to be in the "groups" claim.
				// However, we are configuring Pinniped in the `CreateTestJWTAuthenticatorForCLIUpstream` method above
				// to read the username from the "sub" claim of the token instead.
				username, groups := getJWTSubAndGroupsClaims(t, token)

				return token, username, groups
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := test.authenticator(ctx, t)
			token, username, groups := test.token(t)

			var response *loginv1alpha1.TokenCredentialRequest
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				var err error
				response, err = testlib.CreateTokenCredentialRequest(ctx, t,
					loginv1alpha1.TokenCredentialRequestSpec{Token: token, Authenticator: authenticator},
				)
				requireEventually.NoError(err, "the request should never fail at the HTTP level")
				requireEventually.NotNil(response)
				requireEventually.NotNil(response.Status.Credential, "the response should contain a credential")
				requireEventually.Emptyf(response.Status.Message, "value is: %q", safeDerefStringPtr(response.Status.Message))
				requireEventually.NotNil(response.Status.Credential)
				requireEventually.Empty(response.Spec)
				requireEventually.Empty(response.Status.Credential.Token)
				requireEventually.NotEmpty(response.Status.Credential.ClientCertificateData)
				requireEventually.Equal(username, getCommonName(t, response.Status.Credential.ClientCertificateData))
				requireEventually.ElementsMatch(groups, getOrganizations(t, response.Status.Credential.ClientCertificateData))
				requireEventually.NotEmpty(response.Status.Credential.ClientKeyData)
				requireEventually.NotNil(response.Status.Credential.ExpirationTimestamp)
				requireEventually.InDelta(5*time.Minute, time.Until(response.Status.Credential.ExpirationTimestamp.Time), float64(time.Minute))
			}, 10*time.Second, 500*time.Millisecond)

			// Create a client using the certificate from the CredentialRequest.
			clientWithCertFromCredentialRequest := testlib.NewClientsetWithCertAndKey(
				t,
				response.Status.Credential.ClientCertificateData,
				response.Status.Credential.ClientKeyData,
			)

			t.Run(
				"access as user",
				testlib.AccessAsUserTest(ctx, username, clientWithCertFromCredentialRequest),
			)
			for _, group := range groups {
				t.Run(
					"access as group "+group,
					testlib.AccessAsGroupTest(ctx, group, clientWithCertFromCredentialRequest),
				)
			}
		})
	}
}

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestFailedCredentialRequestWhenTheRequestIsValidButTheTokenDoesNotAuthenticateTheUser_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	// Create a testWebhook so we have a legitimate authenticator to pass to the
	// TokenCredentialRequest API.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	testWebhook := testlib.CreateTestWebhookAuthenticator(ctx, t, &testlib.IntegrationEnv(t).TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

	response, err := testlib.CreateTokenCredentialRequest(context.Background(), t,
		loginv1alpha1.TokenCredentialRequestSpec{Token: "not a good token", Authenticator: testWebhook},
	)

	require.NoError(t, err, testlib.Sdump(err))

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
	require.Equal(t, ptr.To("authentication failed"), response.Status.Message)
}

// TCRs are non-mutating and safe to run in parallel with serial tests, see main_test.go.
func TestCredentialRequest_ShouldFailWhenRequestDoesNotIncludeToken_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	// Create a testWebhook so we have a legitimate authenticator to pass to the
	// TokenCredentialRequest API.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	testWebhook := testlib.CreateTestWebhookAuthenticator(ctx, t, &testlib.IntegrationEnv(t).TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

	response, err := testlib.CreateTokenCredentialRequest(context.Background(), t,
		loginv1alpha1.TokenCredentialRequestSpec{Token: "", Authenticator: testWebhook},
	)

	require.Error(t, err)
	statusError, isStatus := err.(*apierrors.StatusError)
	require.True(t, isStatus, testlib.Sdump(err))

	require.Equal(t, 1, len(statusError.ErrStatus.Details.Causes))
	cause := statusError.ErrStatus.Details.Causes[0]
	require.Equal(t, metav1.CauseType("FieldValueRequired"), cause.Type)
	require.Equal(t, "Required value: token must be supplied", cause.Message)
	require.Equal(t, "spec.token.value", cause.Field)

	require.Empty(t, response.Spec)
	require.Nil(t, response.Status.Credential)
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

func safeDerefStringPtr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func getJWTSubAndGroupsClaims(t *testing.T, jwtToken string) (string, []string) {
	t.Helper()

	token, err := josejwt.ParseSigned(jwtToken, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	require.NoError(t, err)

	var claims struct {
		Sub    string   `json:"sub"`
		Groups []string `json:"groups"`
	}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	return claims.Sub, claims.Groups
}
