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

func TestLDAPIDPPhaseAndConditions_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	supervisorNamespace := testlib.IntegrationEnv(t).SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	ldapIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().LDAPIdentityProviders(supervisorNamespace)

	bindSecret := testlib.CreateTestSecret(
		t,
		env.SupervisorNamespace,
		"ldap-bind-secret",
		corev1.SecretTypeBasicAuth,
		map[string]string{
			corev1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
			corev1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
		},
	)

	wantCABundleMessage := func(caBundleConfigured bool) string {
		if caBundleConfigured {
			return "spec.tls is valid: using configured CA bundle"
		} else {
			return "spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image"
		}
	}

	happySpec := idpv1alpha1.LDAPIdentityProviderSpec{
		Host: env.SupervisorUpstreamLDAP.Host,
		Bind: idpv1alpha1.LDAPIdentityProviderBind{
			SecretName: bindSecret.Name,
		},
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
		},
		UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
			Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
			Filter: "",
			Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
				Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
				UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
			},
		},
		GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
			Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
			Filter: "", // use the default value of "member={}"
			Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
				GroupName: "", // use the default value of "dn"
			},
		},
	}

	tests := []struct {
		name           string
		ldapSpec       idpv1alpha1.LDAPIdentityProviderSpec
		wantPhase      idpv1alpha1.LDAPIdentityProviderPhase
		wantConditions []*metav1.Condition
	}{
		{
			name:      "Happy Path",
			ldapSpec:  happySpec,
			wantPhase: idpv1alpha1.LDAPPhaseReady,
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
						env.SupervisorUpstreamLDAP.Host,
						env.SupervisorUpstreamLDAP.BindUsername,
						bindSecret.Name,
						bindSecret.ResourceVersion),
				},
				{
					Type:    "TLSConfigurationValid",
					Status:  "True",
					Reason:  "Success",
					Message: wantCABundleMessage(len(happySpec.TLS.CertificateAuthorityData) != 0),
				},
			},
		},
		{
			name: "CA bundle is invalid yields conditions TLSConfigurationValid with status 'False' and LDAPConnectionValid/SearchBaseFound with status 'Unknown'",
			ldapSpec: func() idpv1alpha1.LDAPIdentityProviderSpec {
				temp := happySpec.DeepCopy()
				temp.TLS.CertificateAuthorityData = "this-is-not-base64-encoded"
				return *temp
			}(),
			wantPhase: idpv1alpha1.LDAPPhaseError,
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
					Type:    "TLSConfigurationValid",
					Status:  "False",
					Reason:  "InvalidTLSConfig",
					Message: "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 4",
				},
			},
		},
		{
			name: "Bind secret not found yields conditions BindSecretValid with status 'False' and LDAPConnectionValid/SearchBaseFound with status 'Unknown'",
			ldapSpec: func() idpv1alpha1.LDAPIdentityProviderSpec {
				temp := happySpec.DeepCopy()
				temp.Bind.SecretName = "this-secret-does-not-exist"
				return *temp
			}(),
			wantPhase: idpv1alpha1.LDAPPhaseError,
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
					Type:    "TLSConfigurationValid",
					Status:  "True",
					Reason:  "Success",
					Message: wantCABundleMessage(len(happySpec.TLS.CertificateAuthorityData) != 0),
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			idp := testlib.CreateTestLDAPIdentityProvider(t, test.ldapSpec, test.wantPhase)
			testlib.WaitForLDAPIdentityProviderStatusConditions(
				ctx,
				t,
				ldapIDPClient,
				idp.Name,
				test.wantConditions,
			)
		})
	}
}
