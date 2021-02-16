// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestSupervisorUpstreamOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)

	library.AssertNoRestartsDuringTest(t, env.SupervisorNamespace, "")

	t.Run("invalid missing secret and bad issuer", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.OIDCIdentityProviderSpec{
			Issuer: "https://127.0.0.1:444444/issuer",
			Client: v1alpha1.OIDCClient{
				SecretName: "does-not-exist",
			},
		}
		upstream := library.CreateTestOIDCIdentityProvider(t, spec, v1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "SecretNotFound",
				Message: `secret "does-not-exist" not found`,
			},
			{
				Type:    "OIDCDiscoverySucceeded",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "Unreachable",
				Message: `failed to perform OIDC discovery against "https://127.0.0.1:444444/issuer"`,
			},
		})
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorTestUpstream.Issuer,
			TLS: &v1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorTestUpstream.CABundle)),
			},
			AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: v1alpha1.OIDCClient{
				SecretName: library.CreateClientCredsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := library.CreateTestOIDCIdentityProvider(t, spec, v1alpha1.PhaseReady)
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
