// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestSupervisorFederationDomainStatus_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	client := testlib.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t, env.SupervisorNamespace, defaultTLSCertSecretName(env), client, testlib.NewKubernetesClientset(t))

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "valid spec in without explicit identity providers makes status error unless there is exactly one identity provider",
			run: func(t *testing.T) {
				// Creating FederationDomain without any explicit IDPs should put the FederationDomain into an error status.
				fd := testlib.CreateTestFederationDomain(ctx, t, v1alpha1.FederationDomainSpec{
					Issuer: "https://example.com/fake",
				}, v1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(
					allSuccessfulLegacyFederationDomainConditions("", fd.Spec),
					[]v1alpha1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "LegacyConfigurationIdentityProviderNotFound",
							Message: "no resources were specified by .spec.identityProviders[].objectRef and no identity provider resources have been found: please create an identity provider resource",
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
					},
				))

				// Creating an IDP should put the FederationDomain into a successful status.
				oidcIdentityProvider1 := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, idpv1alpha1.PhaseError)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, v1alpha1.FederationDomainPhaseReady)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name,
					allSuccessfulLegacyFederationDomainConditions(oidcIdentityProvider1.Name, fd.Spec))

				// Creating a second IDP should put the FederationDomain back into an error status again.
				oidcIdentityProvider2 := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, idpv1alpha1.PhaseError)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, v1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(
					allSuccessfulLegacyFederationDomainConditions(oidcIdentityProvider2.Name, fd.Spec),
					[]v1alpha1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProviderNotSpecified",
							Message: "no resources were specified by .spec.identityProviders[].objectRef and 2 identity provider " +
								"resources have been found: please update .spec.identityProviders to specify which identity providers " +
								"this federation domain should use",
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
					},
				))
			},
		},
		{
			name: "valid spec with explicit identity providers makes status error until those identity providers all exist",
			run: func(t *testing.T) {
				oidcIDP1Meta := testlib.ObjectMetaWithRandomName(t, "upstream-oidc-idp")
				oidcIDP2Meta := testlib.ObjectMetaWithRandomName(t, "upstream-oidc-idp")
				// Creating FederationDomain with explicit IDPs that don't exist should put the FederationDomain into an error status.
				fd := testlib.CreateTestFederationDomain(ctx, t, v1alpha1.FederationDomainSpec{
					Issuer: "https://example.com/fake",
					IdentityProviders: []v1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "idp1",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: pointer.String("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "OIDCIdentityProvider",
								Name:     oidcIDP1Meta.Name,
							},
							Transforms: v1alpha1.FederationDomainTransforms{},
						},
						{
							DisplayName: "idp2",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: pointer.String("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "OIDCIdentityProvider",
								Name:     oidcIDP2Meta.Name,
							},
							Transforms: v1alpha1.FederationDomainTransforms{},
						},
					},
				}, v1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]v1alpha1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: `.spec.identityProviders[].objectRef identifies resource(s) that cannot be found: .spec.identityProviders[0] with displayName "idp1", .spec.identityProviders[1] with displayName "idp2"`,
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
					},
				))

				// Creating the first IDP should not be enough to put the FederationDomain into a successful status.
				oidcIdentityProvider1 := testlib.CreateTestOIDCIdentityProviderWithObjectMeta(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, oidcIDP1Meta, idpv1alpha1.PhaseError)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, v1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]v1alpha1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: `.spec.identityProviders[].objectRef identifies resource(s) that cannot be found: .spec.identityProviders[1] with displayName "idp2"`,
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
					},
				))

				// Creating the second IDP should put the FederationDomain into a successful status.
				testlib.CreateTestOIDCIdentityProviderWithObjectMeta(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, oidcIDP2Meta, idpv1alpha1.PhaseError)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, v1alpha1.FederationDomainPhaseReady)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name,
					allSuccessfulFederationDomainConditions(fd.Spec))

				// Removing one IDP should put the FederationDomain back into an error status again.
				oidcIDPClient := testlib.NewSupervisorClientset(t).IDPV1alpha1().OIDCIdentityProviders(env.SupervisorNamespace)
				err := oidcIDPClient.Delete(ctx, oidcIdentityProvider1.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, v1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]v1alpha1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: `.spec.identityProviders[].objectRef identifies resource(s) that cannot be found: .spec.identityProviders[0] with displayName "idp1"`,
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
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

func replaceSomeConditions(conditions []v1alpha1.Condition, replaceWithTheseConditions []v1alpha1.Condition) []v1alpha1.Condition {
	cp := make([]v1alpha1.Condition, len(conditions))
	copy(cp, conditions)
	for _, replacementCond := range replaceWithTheseConditions {
		for i, cond := range cp {
			if replacementCond.Type == cond.Type {
				cp[i] = replacementCond
				break
			}
		}
	}
	return cp
}

func allSuccessfulLegacyFederationDomainConditions(idpName string, federationDomainSpec v1alpha1.FederationDomainSpec) []v1alpha1.Condition {
	return replaceSomeConditions(
		allSuccessfulFederationDomainConditions(federationDomainSpec),
		[]v1alpha1.Condition{
			{
				Type: "IdentityProvidersFound", Status: "True", Reason: "LegacyConfigurationSuccess",
				Message: fmt.Sprintf(`no resources were specified by .spec.identityProviders[].objectRef but exactly one `+
					`identity provider resource has been found: using "%s" as identity provider: `+
					`please explicitly list identity providers in .spec.identityProviders `+
					`(this legacy configuration mode may be removed in a future version of Pinniped)`, idpName),
			},
		},
	)
}

func allSuccessfulFederationDomainConditions(federationDomainSpec v1alpha1.FederationDomainSpec) []v1alpha1.Condition {
	return []v1alpha1.Condition{
		{
			Type: "IdentityProvidersDisplayNamesUnique", Status: "True", Reason: "Success",
			Message: "the names specified by .spec.identityProviders[].displayName are unique",
		},
		{
			Type: "IdentityProvidersFound", Status: "True", Reason: "Success",
			Message: "the resources specified by .spec.identityProviders[].objectRef were found",
		},
		{
			Type: "IdentityProvidersObjectRefAPIGroupSuffixValid", Status: "True", Reason: "Success",
			Message: "the API groups specified by .spec.identityProviders[].objectRef.apiGroup are recognized",
		},
		{
			Type: "IdentityProvidersObjectRefKindValid", Status: "True", Reason: "Success",
			Message: "the kinds specified by .spec.identityProviders[].objectRef.kind are recognized",
		},
		{
			Type: "IssuerIsUnique", Status: "True", Reason: "Success",
			Message: "spec.issuer is unique among all FederationDomains",
		},
		{
			Type: "IssuerURLValid", Status: "True", Reason: "Success",
			Message: "spec.issuer is a valid URL",
		},
		{
			Type: "OneTLSSecretPerIssuerHostname", Status: "True", Reason: "Success",
			Message: "all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL",
		},
		{
			Type: "Ready", Status: "True", Reason: "Success",
			Message: fmt.Sprintf("the FederationDomain is ready and its endpoints are available: "+
				"the discovery endpoint is %s/.well-known/openid-configuration", federationDomainSpec.Issuer),
		},
		{
			Type: "TransformsConstantsNamesUnique", Status: "True", Reason: "Success",
			Message: "the names specified by .spec.identityProviders[].transforms.constants[].name are unique",
		},
		{
			Type: "TransformsExamplesPassed", Status: "True", Reason: "Success",
			Message: "the examples specified by .spec.identityProviders[].transforms.examples[] had no errors",
		},
		{
			Type: "TransformsExpressionsValid", Status: "True", Reason: "Success",
			Message: "the expressions specified by .spec.identityProviders[].transforms.expressions[] are valid",
		},
	}
}
