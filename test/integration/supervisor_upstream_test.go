// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestSupervisorUpstreamOIDCDiscovery(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	t.Run("invalid missing secret and bad issuer", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.OIDCIdentityProviderSpec{
			Issuer: "https://127.0.0.1:444444/issuer",
			Client: v1alpha1.OIDCClient{
				SecretName: "does-not-exist",
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, v1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "SecretNotFound",
				Message: `secret "does-not-exist" not found`,
			},
			{
				Type:   "OIDCDiscoverySucceeded",
				Status: v1alpha1.ConditionFalse,
				Reason: "Unreachable",
				Message: `failed to perform OIDC discovery against "https://127.0.0.1:444444/issuer":
Get "https://127.0.0.1:444444/issuer/.well-known/openid-configuration": dial tcp: address 444444: in [truncated 10 chars]`,
			},
		})
	})

	t.Run("invalid issuer with trailing slash", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer + "/",
			TLS: &v1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: v1alpha1.OIDCClient{
				SecretName: testlib.CreateClientCredsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, v1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionTrue,
				Reason:  "Success",
				Message: "loaded client credentials",
			},
			{
				Type:   "OIDCDiscoverySucceeded",
				Status: v1alpha1.ConditionFalse,
				Reason: "Unreachable",
				Message: `failed to perform OIDC discovery against "` + env.SupervisorUpstreamOIDC.Issuer + `/":
oidc: issuer did not match the issuer returned by provider, expected "` + env.SupervisorUpstreamOIDC.Issuer + `/" got "` + env.SupervisorUpstreamOIDC.Issuer + `"`,
			},
		})
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &v1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: v1alpha1.OIDCClient{
				SecretName: testlib.CreateClientCredsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := testlib.CreateTestOIDCIdentityProvider(t, spec, v1alpha1.PhaseReady)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionTrue,
				Reason:  "Success",
				Message: "loaded client credentials",
			},
			{
				Type:    "OIDCDiscoverySucceeded",
				Status:  v1alpha1.ConditionTrue,
				Reason:  "Success",
				Message: "discovered issuer configuration",
			},
		})
	})
}

func expectUpstreamConditions(t *testing.T, upstream *v1alpha1.OIDCIdentityProvider, expected []v1alpha1.Condition) {
	t.Helper()
	normalized := make([]v1alpha1.Condition, 0, len(upstream.Status.Conditions))
	for _, c := range upstream.Status.Conditions {
		c.ObservedGeneration = 0
		c.LastTransitionTime = metav1.Time{}
		normalized = append(normalized, c)
	}
	require.ElementsMatch(t, expected, normalized)
}
