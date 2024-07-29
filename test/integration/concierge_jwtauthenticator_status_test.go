// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestConciergeJWTAuthenticatorWithExternalCABundleStatusIsUpdatedWhenExternalBundleIsUpdated_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	client := testlib.NewKubernetesClientset(t)

	tests := []struct {
		name                      string
		caBundleSourceSpecKind    string
		createResourceForCABundle func(t *testing.T, caBundle string) string
		updateCABundle            func(t *testing.T, resourceName, caBundle string)
	}{
		{
			name:                   "for a CA bundle from a ConfigMap",
			caBundleSourceSpecKind: "ConfigMap",
			createResourceForCABundle: func(t *testing.T, caBundle string) string {
				createdResource := testlib.CreateTestConfigMap(t, env.ConciergeNamespace, "ca-bundle", map[string]string{
					"ca.crt": caBundle,
				})
				return createdResource.Name
			},
			updateCABundle: func(t *testing.T, resourceName, caBundle string) {
				configMap, err := client.CoreV1().ConfigMaps(env.ConciergeNamespace).Get(ctx, resourceName, metav1.GetOptions{})
				require.NoError(t, err)

				configMap.Data["ca.crt"] = caBundle

				_, err = client.CoreV1().ConfigMaps(env.ConciergeNamespace).Update(ctx, configMap, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
		},
		{
			name:                   "for a CA bundle from a Secret",
			caBundleSourceSpecKind: "Secret",
			createResourceForCABundle: func(t *testing.T, caBundle string) string {
				createdResource := testlib.CreateTestSecret(t, env.ConciergeNamespace, "ca-bundle", corev1.SecretTypeOpaque, map[string]string{
					"ca.crt": caBundle,
				})
				return createdResource.Name
			},
			updateCABundle: func(t *testing.T, resourceName, caBundle string) {
				secret, err := client.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, resourceName, metav1.GetOptions{})
				require.NoError(t, err)

				secret.Data["ca.crt"] = []byte(caBundle)

				_, err = client.CoreV1().Secrets(env.ConciergeNamespace).Update(ctx, secret, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Run several times because there is always a chance that the test could pass because the controller
			// will resync every 3 minutes even if it does not pay attention to changes in ConfigMaps and Secrets.
			for i := range 3 {
				t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
					t.Parallel()

					caBundleResourceName := test.createResourceForCABundle(t, env.SupervisorUpstreamOIDC.CABundle)

					authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, authenticationv1alpha1.JWTAuthenticatorSpec{
						Issuer:   env.SupervisorUpstreamOIDC.Issuer,
						Audience: "does-not-matter",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
								Kind: test.caBundleSourceSpecKind,
								Name: caBundleResourceName,
								Key:  "ca.crt",
							},
						},
					}, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

					test.updateCABundle(t, caBundleResourceName, "this is not a valid CA bundle value")
					testlib.WaitForJWTAuthenticatorStatusPhase(ctx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseError)

					test.updateCABundle(t, caBundleResourceName, env.SupervisorUpstreamOIDC.CABundle)
					testlib.WaitForJWTAuthenticatorStatusPhase(ctx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)
				})
			}
		})
	}
}

func TestConciergeJWTAuthenticatorStatus_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	tests := []struct {
		name           string
		spec           authenticationv1alpha1.JWTAuthenticatorSpec
		wantPhase      authenticationv1alpha1.JWTAuthenticatorPhase
		wantConditions []metav1.Condition
	}{
		{
			name: "valid spec with no errors and all good status conditions and phase will result in a jwt authenticator that is ready",
			spec: authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   env.SupervisorUpstreamOIDC.Issuer,
				Audience: "some-fake-audience",
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
				},
			},
			wantPhase:      authenticationv1alpha1.JWTAuthenticatorPhaseReady,
			wantConditions: allSuccessfulJWTAuthenticatorConditions(true),
		},
		{
			name: "valid spec with invalid CA in TLS config will result in a jwt authenticator that is not ready",
			spec: authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   env.SupervisorUpstreamOIDC.Issuer,
				Audience: "some-fake-audience",
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: "invalid base64-encoded data",
				},
			},
			wantPhase: authenticationv1alpha1.JWTAuthenticatorPhaseError,
			wantConditions: replaceSomeConditions(
				allSuccessfulJWTAuthenticatorConditions(true),
				[]metav1.Condition{
					{
						Type:    "Ready",
						Status:  "False",
						Reason:  "NotReady",
						Message: "the JWTAuthenticator is not ready: see other conditions for details",
					}, {
						Type:    "AuthenticatorValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSURLValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSFetchValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "DiscoveryURLValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "TLSConfigurationValid",
						Status:  "False",
						Reason:  "InvalidTLSConfig",
						Message: "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7",
					},
				},
			),
		},
		{
			name: "valid spec with valid CA in TLS config but does not match issuer server will result in a jwt authenticator that is not ready",
			spec: authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   env.SupervisorUpstreamOIDC.Issuer,
				Audience: "some-fake-audience",
				// Some random generated cert
				// Issuer: C=US, O=Pivotal
				// No SAN provided
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lWQUpzNStTbVRtaTJXeUI0bGJJRXBXaUs5a1RkUE1BMEdDU3FHU0liM0RRRUIKQ3dVQU1COHhDekFKQmdOVkJBWVRBbFZUTVJBd0RnWURWUVFLREFkUWFYWnZkR0ZzTUI0WERUSXdNRFV3TkRFMgpNamMxT0ZvWERUSTBNRFV3TlRFMk1qYzFPRm93SHpFTE1Ba0dBMVVFQmhNQ1ZWTXhFREFPQmdOVkJBb01CMUJwCmRtOTBZV3d3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRERZWmZvWGR4Z2NXTEMKZEJtbHB5a0tBaG9JMlBuUWtsVFNXMno1cGcwaXJjOGFRL1E3MXZzMTRZYStmdWtFTGlvOTRZYWw4R01DdVFrbApMZ3AvUEE5N1VYelhQNDBpK25iNXcwRGpwWWd2dU9KQXJXMno2MFRnWE5NSFh3VHk4ME1SZEhpUFVWZ0VZd0JpCmtkNThzdEFVS1Y1MnBQTU1reTJjNy9BcFhJNmRXR2xjalUvaFBsNmtpRzZ5dEw2REtGYjJQRWV3MmdJM3pHZ2IKOFVVbnA1V05DZDd2WjNVY0ZHNXlsZEd3aGc3cnZ4U1ZLWi9WOEhCMGJmbjlxamlrSVcxWFM4dzdpUUNlQmdQMApYZWhKZmVITlZJaTJtZlczNlVQbWpMdnVKaGpqNDIrdFBQWndvdDkzdWtlcEgvbWpHcFJEVm9wamJyWGlpTUYrCkYxdnlPNGMxQWdNQkFBR2pnWU13Z1lBd0hRWURWUjBPQkJZRUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1IKTUI4R0ExVWRJd1FZTUJhQUZNTWJpSXFhdVkwajRVWWphWDl0bDJzby9LQ1JNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BNEdBMVVkRHdFQi93UUVBd0lCCkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFYbEh4M2tIMDZwY2NDTDlEVE5qTnBCYnlVSytGd2R6T2IwWFYKcmpNaGtxdHVmdEpUUnR5T3hKZ0ZKNXhUR3pCdEtKamcrVU1pczBOV0t0VDBNWThVMU45U2c5SDl0RFpHRHBjVQpxMlVRU0Y4dXRQMVR3dnJIUzIrdzB2MUoxdHgrTEFiU0lmWmJCV0xXQ21EODUzRlVoWlFZekkvYXpFM28vd0p1CmlPUklMdUpNUk5vNlBXY3VLZmRFVkhaS1RTWnk3a25FcHNidGtsN3EwRE91eUFWdG9HVnlkb3VUR0FOdFhXK2YKczNUSTJjKzErZXg3L2RZOEJGQTFzNWFUOG5vZnU3T1RTTzdiS1kzSkRBUHZOeFQzKzVZUXJwNGR1Nmh0YUFMbAppOHNaRkhidmxpd2EzdlhxL3p1Y2JEaHEzQzBhZnAzV2ZwRGxwSlpvLy9QUUFKaTZLQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
				},
			},
			wantPhase: authenticationv1alpha1.JWTAuthenticatorPhaseError,
			wantConditions: replaceSomeConditions(
				allSuccessfulJWTAuthenticatorConditions(true),
				[]metav1.Condition{
					{
						Type:    "Ready",
						Status:  "False",
						Reason:  "NotReady",
						Message: "the JWTAuthenticator is not ready: see other conditions for details",
					}, {
						Type:    "AuthenticatorValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSURLValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSFetchValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "DiscoveryURLValid",
						Status:  "False",
						Reason:  "InvalidDiscoveryProbe",
						Message: `could not perform oidc discovery on provider issuer: Get "` + env.SupervisorUpstreamOIDC.Issuer + `/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority`,
					}, {
						Type:    "TLSConfigurationValid",
						Status:  "True",
						Reason:  "Success",
						Message: "spec.tls is valid: using configured CA bundle",
					},
				},
			),
		},
		{
			name: "invalid with bad issuer will result in a jwt authenticator that is not ready",
			spec: authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   env.SupervisorUpstreamOIDC.Issuer + "/this-is-the-wrong-path",
				Audience: "some-fake-audience",
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
				},
			},
			wantPhase: authenticationv1alpha1.JWTAuthenticatorPhaseError,
			wantConditions: replaceSomeConditions(
				allSuccessfulJWTAuthenticatorConditions(true),
				[]metav1.Condition{
					{
						Type:    "Ready",
						Status:  "False",
						Reason:  "NotReady",
						Message: "the JWTAuthenticator is not ready: see other conditions for details",
					}, {
						Type:    "AuthenticatorValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSURLValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "JWKSFetchValid",
						Status:  "Unknown",
						Reason:  "UnableToValidate",
						Message: "unable to validate; see other conditions for details",
					}, {
						Type:    "DiscoveryURLValid",
						Status:  "False",
						Reason:  "InvalidDiscoveryProbe",
						Message: "could not perform oidc discovery on provider issuer: 404 Not Found: 404 page not found\n",
					},
				},
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			jwtAuthenticator := testlib.CreateTestJWTAuthenticator(ctx, t, test.spec, test.wantPhase)
			testlib.WaitForJWTAuthenticatorStatusConditions(ctx, t, jwtAuthenticator.Name, test.wantConditions)
		})
	}
}

func TestConciergeJWTAuthenticatorCRDValidations_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	jwtAuthenticatorClient := testlib.NewConciergeClientset(t).AuthenticationV1alpha1().JWTAuthenticators()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	objectMeta := testlib.ObjectMetaWithRandomName(t, "jwt-authenticator")
	tests := []struct {
		name             string
		jwtAuthenticator *authenticationv1alpha1.JWTAuthenticator
		wantErr          string
	}{
		{
			name: "issuer can not be empty string",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   "",
					Audience: "fake-audience",
				},
			},
			wantErr: `JWTAuthenticator.authentication.concierge.` + env.APIGroupSuffix + ` "` + objectMeta.Name + `" is invalid: ` +
				`spec.issuer: Invalid value: "": spec.issuer in body should be at least 1 chars long`,
		},
		{
			name: "audience can not be empty string",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://example.com",
					Audience: "",
				},
			},
			wantErr: `JWTAuthenticator.authentication.concierge.` + env.APIGroupSuffix + ` "` + objectMeta.Name + `" is invalid: ` +
				`spec.audience: Invalid value: "": spec.audience in body should be at least 1 chars long`,
		},
		{
			name: "issuer must be https",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   "http://www.example.com",
					Audience: "foo",
				},
			},
			wantErr: `JWTAuthenticator.authentication.concierge.` + env.APIGroupSuffix + ` "` + objectMeta.Name + `" is invalid: ` +
				`spec.issuer: Invalid value: "http://www.example.com": spec.issuer in body should match '^https://'`,
		},
		{
			name: "minimum valid authenticator",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: "foo",
				},
			},
		},
		{
			name: "valid authenticator can have empty claims block",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: "foo",
					Claims:   authenticationv1alpha1.JWTTokenClaims{},
				},
			},
		},
		{
			name: "valid authenticator can have empty group claim and empty username claim",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: "foo",
					Claims: authenticationv1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
				},
			},
		},
		{
			name: "valid authenticator can have empty TLS block",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: "foo",
					Claims: authenticationv1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
					TLS: &authenticationv1alpha1.TLSSpec{},
				},
			},
		},
		{
			name: "valid authenticator can have empty TLS CertificateAuthorityData",
			jwtAuthenticator: &authenticationv1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.CLIUpstreamOIDC.Issuer,
					Audience: "foo",
					Claims: authenticationv1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
					TLS: &authenticationv1alpha1.TLSSpec{
						CertificateAuthorityData: "pretend-this-is-a-certificate",
					},
				},
			},
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, createErr := jwtAuthenticatorClient.Create(ctx, tt.jwtAuthenticator, metav1.CreateOptions{})

			t.Cleanup(func() {
				// delete if it exists
				delErr := jwtAuthenticatorClient.Delete(ctx, tt.jwtAuthenticator.Name, metav1.DeleteOptions{})
				if !apierrors.IsNotFound(delErr) {
					require.NoError(t, delErr)
				}
			})

			if tt.wantErr != "" {
				wantErr := tt.wantErr
				require.EqualError(t, createErr, wantErr)
			} else {
				require.NoError(t, createErr)
			}
		})
	}
}

func allSuccessfulJWTAuthenticatorConditions(caBundleExists bool) []metav1.Condition {
	tlsConfigValidMsg := "no CA bundle specified"
	if caBundleExists {
		tlsConfigValidMsg = "spec.tls is valid: using configured CA bundle"
	}
	return []metav1.Condition{{
		Type:    "AuthenticatorValid",
		Status:  "True",
		Reason:  "Success",
		Message: "authenticator initialized",
	}, {
		Type:    "DiscoveryURLValid",
		Status:  "True",
		Reason:  "Success",
		Message: "discovery performed successfully",
	}, {
		Type:    "IssuerURLValid",
		Status:  "True",
		Reason:  "Success",
		Message: "issuer is a valid URL",
	}, {
		Type:    "JWKSFetchValid",
		Status:  "True",
		Reason:  "Success",
		Message: "successfully fetched jwks",
	}, {
		Type:    "JWKSURLValid",
		Status:  "True",
		Reason:  "Success",
		Message: "jwks_uri is a valid URL",
	}, {
		Type:    "Ready",
		Status:  "True",
		Reason:  "Success",
		Message: "the JWTAuthenticator is ready",
	}, {
		Type:    "TLSConfigurationValid",
		Status:  "True",
		Reason:  "Success",
		Message: tlsConfigValidMsg,
	}}
}
