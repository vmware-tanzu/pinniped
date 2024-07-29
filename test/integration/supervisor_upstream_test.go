// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestSupervisorUpstreamOIDCDiscovery(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	t.Run("invalid missing secret and bad issuer", func(t *testing.T) {
		t.Parallel()
		spec := idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: "https://127.0.0.1:444444/invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			Client: idpv1alpha1.OIDCClient{
				SecretName: "does-not-exist",
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []metav1.Condition{
			{
				Type:    "ClientCredentialsSecretValid",
				Status:  metav1.ConditionFalse,
				Reason:  "SecretNotFound",
				Message: `secret "does-not-exist" not found`,
			},
			{
				Type:   "OIDCDiscoverySucceeded",
				Status: metav1.ConditionFalse,
				Reason: "Unreachable",
				Message: `failed to perform OIDC discovery against "https://127.0.0.1:444444/invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":
Get "https://127.0.0.1:444444/invalid-url-that-is-really-really-long-nanananananananannanananan-batman-nanananananananananananananana-batman-lalalalalalalalalal-batman-weeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/.well-known/openid-configuration": dial tcp: address 444444: in [truncated 10 chars]`,
			},
			{
				Type:    "AdditionalAuthorizeParametersValid",
				Status:  "True",
				Reason:  "Success",
				Message: "additionalAuthorizeParameters parameter names are allowed",
			},
			{
				Type:    "TLSConfigurationValid",
				Status:  "True",
				Reason:  "Success",
				Message: `spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image`,
			},
		})
	})

	t.Run("invalid issuer with trailing slash", func(t *testing.T) {
		t.Parallel()
		spec := idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer + "/",
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []metav1.Condition{
			{
				Type:    "ClientCredentialsSecretValid",
				Status:  metav1.ConditionTrue,
				Reason:  "Success",
				Message: "loaded client credentials",
			},
			{
				Type:   "OIDCDiscoverySucceeded",
				Status: metav1.ConditionFalse,
				Reason: "Unreachable",
				Message: `failed to perform OIDC discovery against "` + env.SupervisorUpstreamOIDC.Issuer + `/":
oidc: issuer did not match the issuer returned by provider, expected "` + env.SupervisorUpstreamOIDC.Issuer + `/" got "` + env.SupervisorUpstreamOIDC.Issuer + `"`,
			},
			{
				Type:    "AdditionalAuthorizeParametersValid",
				Status:  "True",
				Reason:  "Success",
				Message: "additionalAuthorizeParameters parameter names are allowed",
			},
			{
				Type:    "TLSConfigurationValid",
				Status:  "True",
				Reason:  "Success",
				Message: `spec.tls is valid: using configured CA bundle`,
			},
		})
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		spec := idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, idpv1alpha1.PhaseReady)
		expectUpstreamConditions(t, upstream, []metav1.Condition{
			{
				Type:    "ClientCredentialsSecretValid",
				Status:  metav1.ConditionTrue,
				Reason:  "Success",
				Message: "loaded client credentials",
			},
			{
				Type:    "OIDCDiscoverySucceeded",
				Status:  metav1.ConditionTrue,
				Reason:  "Success",
				Message: "discovered issuer configuration",
			},
			{
				Type:    "AdditionalAuthorizeParametersValid",
				Status:  "True",
				Reason:  "Success",
				Message: "additionalAuthorizeParameters parameter names are allowed",
			},
			{
				Type:    "TLSConfigurationValid",
				Status:  "True",
				Reason:  "Success",
				Message: `spec.tls is valid: using configured CA bundle`,
			},
		})
	})
}

func expectUpstreamConditions(t *testing.T, upstream *idpv1alpha1.OIDCIdentityProvider, expected []metav1.Condition) {
	t.Helper()
	normalized := make([]metav1.Condition, 0, len(upstream.Status.Conditions))
	for _, c := range upstream.Status.Conditions {
		c.ObservedGeneration = 0
		c.LastTransitionTime = metav1.Time{}
		normalized = append(normalized, c)
	}
	require.ElementsMatch(t, expected, normalized)
}
