// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestActiveDirectoryIDPPhaseAndConditions_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)

	supervisorNamespace := testlib.IntegrationEnv(t).SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	adIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().ActiveDirectoryIdentityProviders(supervisorNamespace)

	bindSecret := testlib.CreateTestSecret(
		t,
		env.SupervisorNamespace,
		"ad-bind-secret",
		corev1.SecretTypeBasicAuth,
		map[string]string{
			corev1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
			corev1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
		},
	)

	happySpec := idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
		Host: env.SupervisorUpstreamActiveDirectory.Host,
		Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
			SecretName: bindSecret.Name,
		},
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
		},
		UserSearch: idpv1alpha1.ActiveDirectoryIdentityProviderUserSearch{
			Base:   env.SupervisorUpstreamActiveDirectory.UserSearchBase,
			Filter: "",
			Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderUserSearchAttributes{
				Username: env.SupervisorUpstreamActiveDirectory.TestUserMailAttributeName,
				UID:      env.SupervisorUpstreamActiveDirectory.TestUserUniqueIDAttributeName,
			},
		},
		GroupSearch: idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearch{
			Base:   env.SupervisorUpstreamActiveDirectory.GroupSearchBase,
			Filter: "", // use the default value of "member={}"
			Attributes: idpv1alpha1.ActiveDirectoryIdentityProviderGroupSearchAttributes{
				GroupName: "", // use the default value of "dn"
			},
		},
	}

	tests := []struct {
		name           string
		adSpec         idpv1alpha1.ActiveDirectoryIdentityProviderSpec
		wantPhase      idpv1alpha1.ActiveDirectoryIdentityProviderPhase
		wantConditions []*metav1.Condition
	}{
		{
			name:      "Happy Path",
			adSpec:    happySpec,
			wantPhase: idpv1alpha1.ActiveDirectoryPhaseReady,
			wantConditions: []*metav1.Condition{
				{
					Type:    "BindSecretValid",
					Status:  "True",
					Reason:  "Success",
					Message: "loaded bind secret",
				},
				{
					Type:   "LDAPConnectionValid",
					Status: "True",
					Reason: "Success",
					Message: fmt.Sprintf(
						`successfully able to connect to %q and bind as user %q [validated with Secret %q at version %q]`,
						env.SupervisorUpstreamActiveDirectory.Host,
						env.SupervisorUpstreamActiveDirectory.BindUsername,
						bindSecret.Name,
						bindSecret.ResourceVersion),
				},
				{
					Type:    "SearchBaseFound",
					Status:  "True",
					Reason:  "UsingConfigurationFromSpec",
					Message: "Using search base from ActiveDirectoryIdentityProvider config.",
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  "True",
					Reason:  "Success",
					Message: "spec.tls is valid: using configured CA bundle",
				},
			},
		},
		{
			name: "CA bundle is invalid yields conditions TLSConfigurationValid with status 'False' and LDAPConnectionValid with status 'Unknown'",
			adSpec: func() idpv1alpha1.ActiveDirectoryIdentityProviderSpec {
				temp := happySpec.DeepCopy()
				temp.TLS.CertificateAuthorityData = "this-is-not-base64-encoded"
				return *temp
			}(),
			wantPhase: idpv1alpha1.ActiveDirectoryPhaseError,
			wantConditions: []*metav1.Condition{
				{
					Type:    "BindSecretValid",
					Status:  "True",
					Reason:  "Success",
					Message: "loaded bind secret",
				},
				{
					Type:    "LDAPConnectionValid",
					Status:  "Unknown",
					Reason:  "UnableToValidate",
					Message: "unable to validate; see other conditions for details",
				},
				{
					Type:    "SearchBaseFound",
					Status:  "Unknown",
					Reason:  "UnableToValidate",
					Message: "unable to validate; see other conditions for details",
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  "False",
					Reason:  "InvalidTLSConfig",
					Message: "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 4",
				},
			},
		},
		{
			name: "Bind secret not found yields conditions BindSecretValid with status 'False' and LDAPConnectionValid with status 'Unknown'",
			adSpec: func() idpv1alpha1.ActiveDirectoryIdentityProviderSpec {
				temp := happySpec.DeepCopy()
				temp.Bind.SecretName = "this-secret-does-not-exist"
				return *temp
			}(),
			wantPhase: idpv1alpha1.ActiveDirectoryPhaseError,
			wantConditions: []*metav1.Condition{
				{
					Type:    "BindSecretValid",
					Status:  "False",
					Reason:  "SecretNotFound",
					Message: `secret "this-secret-does-not-exist" not found`,
				},
				{
					Type:    "LDAPConnectionValid",
					Status:  "Unknown",
					Reason:  "UnableToValidate",
					Message: "unable to validate; see other conditions for details",
				},
				{
					Type:    "SearchBaseFound",
					Status:  "Unknown",
					Reason:  "UnableToValidate",
					Message: "unable to validate; see other conditions for details",
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  "True",
					Reason:  "Success",
					Message: "spec.tls is valid: using configured CA bundle",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			idp := testlib.CreateTestActiveDirectoryIdentityProvider(t, test.adSpec, test.wantPhase)
			testlib.WaitForActiveDirectoryIdentityProviderStatusConditions(
				ctx,
				t,
				adIDPClient,
				idp.Name,
				test.wantConditions,
			)
		})
	}
}
