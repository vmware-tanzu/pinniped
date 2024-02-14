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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestConciergeJWTAuthenticatorStatus_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "valid spec with no errors and all good status conditions and phase",
			run: func(t *testing.T) {
				jwtAuthenticator := testlib.CreateTestJWTAuthenticator(ctx, t, v1alpha1.JWTAuthenticatorSpec{
					Issuer:   env.SupervisorUpstreamOIDC.Issuer,
					Audience: "some-fake-audience",
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
				}, v1alpha1.JWTAuthenticatorPhaseReady)

				testlib.WaitForJWTAuthenticatorStatusConditions(
					ctx, t,
					jwtAuthenticator.Name,
					allSuccessfulJWTAuthenticatorConditions())
			},
		}, {
			name: "invalid with bad issuer",
			run: func(t *testing.T) {
				fakeIssuerURL := "https://127.0.0.1:443/some-fake-issuer"
				jwtAuthenticator := testlib.CreateTestJWTAuthenticator(ctx, t, v1alpha1.JWTAuthenticatorSpec{
					Issuer:   fakeIssuerURL,
					Audience: "some-fake-audience",
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
					},
				}, v1alpha1.JWTAuthenticatorPhaseError)

				testlib.WaitForJWTAuthenticatorStatusConditions(
					ctx, t,
					jwtAuthenticator.Name,
					replaceSomeConditions(
						allSuccessfulJWTAuthenticatorConditions(),
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
								Message: "unable to validate; other issues present",
							}, {
								Type:    "JWKSURLValid",
								Status:  "Unknown",
								Reason:  "UnableToValidate",
								Message: "unable to validate; other issues present",
							}, {
								Type:    "DiscoveryURLValid",
								Status:  "False",
								Reason:  "InvalidDiscoveryProbe",
								Message: fmt.Sprintf(`could not perform oidc discovery on provider issuer: Get "%s/.well-known/openid-configuration": dial tcp 127.0.0.1:443: connect: connection refused`, fakeIssuerURL),
							},
						},
					))
			},
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t)
		})
	}
}

func TestConciergeJWTAuthenticatorCRDValidations_Parallel(t *testing.T) {
	jwtAuthenticatorClient := testlib.NewConciergeClientset(t).AuthenticationV1alpha1().JWTAuthenticators()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	objectMeta := testlib.ObjectMetaWithRandomName(t, "jwt-authenticator")
	tests := []struct {
		name             string
		jwtAuthenticator *v1alpha1.JWTAuthenticator
		wantErr          string
		// some tests change the environment (api group suffix pinniped.dev->walrus.tld) so
		// we need to be able to compare against several error strings
		wantOneOfErr []string
	}{
		{
			name: "issuer can not be empty string",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "",
					Audience: "fake-audience",
				},
			},
			wantOneOfErr: []string{
				`JWTAuthenticator.authentication.concierge.pinniped.dev "` + objectMeta.Name + `" is invalid: ` +
					`spec.issuer: Invalid value: "": spec.issuer in body should be at least 1 chars long`,
				`JWTAuthenticator.authentication.concierge.walrus.tld "` + objectMeta.Name + `" is invalid: ` +
					`spec.issuer: Invalid value: "": spec.issuer in body should be at least 1 chars long`,
			},
		},
		{
			name: "audience can not be empty string",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://example.com",
					Audience: "",
				},
			},
			wantOneOfErr: []string{
				`JWTAuthenticator.authentication.concierge.pinniped.dev "` + objectMeta.Name + `" is invalid: ` +
					`spec.audience: Invalid value: "": spec.audience in body should be at least 1 chars long`,
				`JWTAuthenticator.authentication.concierge.walrus.tld "` + objectMeta.Name + `" is invalid: ` +
					`spec.audience: Invalid value: "": spec.audience in body should be at least 1 chars long`,
			},
		},
		{
			name: "issuer must be https",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "http://www.example.com",
					Audience: "foo",
				},
			},
			wantOneOfErr: []string{
				`JWTAuthenticator.authentication.concierge.pinniped.dev "` + objectMeta.Name + `" is invalid: ` +
					`spec.issuer: Invalid value: "http://www.example.com": spec.issuer in body should match '^https://'`,
				`JWTAuthenticator.authentication.concierge.walrus.tld "` + objectMeta.Name + `" is invalid: ` +
					`spec.issuer: Invalid value: "http://www.example.com": spec.issuer in body should match '^https://'`,
			},
		},
		{
			name: "minimum valid authenticator",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://www.example.com",
					Audience: "foo",
				},
			},
		},
		{
			name: "minimum valid authenticator can have empty claims block",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://www.example.com",
					Audience: "foo",
					Claims:   v1alpha1.JWTTokenClaims{},
				},
			},
		},
		{
			name: "minimum valid authenticator can have empty group claim and empty username claim",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://www.example.com",
					Audience: "foo",
					Claims: v1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
				},
			},
		},
		{
			name: "minimum valid authenticator can have empty TLS block",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://www.example.com",
					Audience: "foo",
					Claims: v1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
					TLS: &v1alpha1.TLSSpec{},
				},
			},
		},
		{
			name: "minimum valid authenticator can have empty TLS CertificateAuthorityData",
			jwtAuthenticator: &v1alpha1.JWTAuthenticator{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "jwtauthenticator"),
				Spec: v1alpha1.JWTAuthenticatorSpec{
					Issuer:   "https://www.example.com",
					Audience: "foo",
					Claims: v1alpha1.JWTTokenClaims{
						Groups:   "",
						Username: "",
					},
					TLS: &v1alpha1.TLSSpec{
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
				if !errors.IsNotFound(delErr) {
					require.NoError(t, delErr)
				}
			})

			if tt.wantErr != "" && tt.wantOneOfErr != nil {
				require.NoError(t, fmt.Errorf("test '%s' should not use both tt.wantErr and tt.wantOneOfErr", tt.name))
			}

			if tt.wantErr == "" && tt.wantOneOfErr == nil {
				require.NoError(t, createErr)
			}

			if tt.wantErr != "" {
				wantErr := tt.wantErr
				require.EqualError(t, createErr, wantErr)
			}
			if tt.wantOneOfErr != nil {
				wantOneOfErr := tt.wantOneOfErr
				require.Contains(t, wantOneOfErr, createErr.Error())
			}
		})
	}
}

func allSuccessfulJWTAuthenticatorConditions() []metav1.Condition {
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
		Message: "valid TLS configuration",
	}}
}
