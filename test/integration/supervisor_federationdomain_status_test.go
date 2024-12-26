// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
)

// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestSupervisorFederationDomainStatus_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	supervisorClient := testlib.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t,
		env.SupervisorNamespace, env.DefaultTLSCertSecretName(), supervisorClient, testlib.NewKubernetesClientset(t))

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "valid spec in without explicit identity providers makes status error unless there is exactly one identity provider",
			run: func(t *testing.T) {
				// Creating FederationDomain without any explicit IDPs should put the FederationDomain into an error status.
				fd := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com/fake",
				}, supervisorconfigv1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulLegacyFederationDomainConditions(t, "", fd.Spec),
					[]metav1.Condition{
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
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name,
					allSuccessfulLegacyFederationDomainConditions(t, oidcIdentityProvider1.Name, fd.Spec))

				// Creating a second IDP should put the FederationDomain back into an error status again.
				oidcIdentityProvider2 := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, idpv1alpha1.PhaseError)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulLegacyFederationDomainConditions(t, oidcIdentityProvider2.Name, fd.Spec),
					[]metav1.Condition{
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
				fd := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com/fake",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "idp1",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "OIDCIdentityProvider",
								Name:     oidcIDP1Meta.Name,
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{},
						},
						{
							DisplayName: "idp2",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "OIDCIdentityProvider",
								Name:     oidcIDP2Meta.Name,
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{},
						},
					},
				}, supervisorconfigv1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]metav1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: here.Docf(`
								cannot find resource specified by .spec.identityProviders[0].objectRef (with name "%s")

								cannot find resource specified by .spec.identityProviders[1].objectRef (with name "%s")`,
								oidcIDP1Meta.Name, oidcIDP2Meta.Name),
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
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]metav1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: fmt.Sprintf(`cannot find resource specified by .spec.identityProviders[1].objectRef (with name "%s")`, oidcIDP2Meta.Name),
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
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name,
					allSuccessfulFederationDomainConditions(fd.Spec))

				// Removing one IDP should put the FederationDomain back into an error status again.
				oidcIDPClient := supervisorClient.IDPV1alpha1().OIDCIdentityProviders(env.SupervisorNamespace)
				err := oidcIDPClient.Delete(ctx, oidcIdentityProvider1.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseError)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]metav1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: fmt.Sprintf(`cannot find resource specified by .spec.identityProviders[0].objectRef (with name "%s")`, oidcIDP1Meta.Name),
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
			name: "spec with explicit identity providers and lots of validation errors",
			run: func(t *testing.T) {
				federationDomainsClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(env.SupervisorNamespace)

				oidcIdentityProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
					Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
					Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
				}, idpv1alpha1.PhaseError)

				fd := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com/fake",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "not unique",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("this is the wrong api group"),
								Kind:     "OIDCIdentityProvider",
								Name:     "will not be found",
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "foo", Type: "string", StringValue: "bar"},
								},
								Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
									{Type: "username/v1", Expression: "this is not a valid cel expression"},
									{Type: "groups/v1", Expression: "this is also not a valid cel expression"},
									{Type: "username/v1", Expression: "username"}, // valid
									{Type: "policy/v1", Expression: "still not a valid cel expression"},
								},
								Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
									{
										Username: "does not matter because expressions did not compile",
									},
								},
							},
						},
						{ // this identity provider should be valid
							DisplayName: "unique",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "OIDCIdentityProvider",
								Name:     oidcIdentityProvider.Name,
							},
						},
						{
							DisplayName: "not unique",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
								Kind:     "this is the wrong kind",
								Name:     "also will not be found",
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "ryan", Type: "string", StringValue: "ryan"},
									{Name: "unused", Type: "stringList", StringListValue: []string{"foo", "bar"}},
									{Name: "rejectMe", Type: "string", StringValue: "rejectMeWithDefaultMessage"},
								},
								Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
									{Type: "policy/v1", Expression: `username == strConst.ryan || username == strConst.rejectMe`, Message: "only special users allowed"},
									{Type: "policy/v1", Expression: `username != "rejectMeWithDefaultMessage"`}, // no message specified
									{Type: "username/v1", Expression: `"pre:" + username`},
									{Type: "groups/v1", Expression: `groups.map(g, "pre:" + g)`},
								},
								Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
									{ // this example should pass
										Username: "ryan",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Username: "pre:ryan",
											Groups:   []string{"pre:b", "pre:a", "pre:b", "pre:a"}, // order and repeats don't matter, treated like a set
											Rejected: false,
										},
									},
									{ // this example should pass
										Username: "other",
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Rejected: true,
											Message:  "only special users allowed",
										},
									},
									{ // this example should fail because it expects the user to be rejected but the user was actually not rejected
										Username: "ryan",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Rejected: true,
											Message:  "this input is ignored in this case",
										},
									},
									{ // this example should fail because it expects the user not to be rejected but they were actually rejected
										Username: "other",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Username: "pre:other",
											Groups:   []string{"pre:a", "pre:b"},
											Rejected: false,
										},
									},
									{ // this example should fail because it expects the wrong rejection message
										Username: "other",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Rejected: true,
											Message:  "wrong message",
										},
									},
									{ // this example should pass even though it does not make any assertion about the rejection message
										// because the message assertions defaults to asserting the default rejection message
										Username: "rejectMeWithDefaultMessage",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Rejected: true,
										},
									},
									{ // this example should fail because it expects both the wrong username and groups
										Username: "ryan",
										Groups:   []string{"b", "a"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Username: "wrong",
											Groups:   []string{},
											Rejected: false,
										},
									},
									{ // this example should fail because it expects the wrong username only
										Username: "ryan",
										Groups:   []string{"a", "b"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Username: "wrong",
											Groups:   []string{"pre:b", "pre:a"},
											Rejected: false,
										},
									},
									{ // this example should fail because it expects the wrong groups only
										Username: "ryan",
										Groups:   []string{"b", "a"},
										Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
											Username: "pre:ryan",
											Groups:   []string{"wrong2", "wrong1"},
											Rejected: false,
										},
									},
									{ // this example should fail because it does not expect anything but the auth actually was successful
										Username: "ryan",
										Groups:   []string{"b", "a"},
										Expects:  supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{},
									},
								},
							},
						},
					},
				}, supervisorconfigv1alpha1.FederationDomainPhaseError)

				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]metav1.Condition{
						{
							Type: "IdentityProvidersDisplayNamesUnique", Status: "False", Reason: "DuplicateDisplayNames",
							Message: `the names specified by .spec.identityProviders[].displayName contain duplicates: "not unique"`,
						},
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: here.Doc(
								`cannot find resource specified by .spec.identityProviders[0].objectRef (with name "will not be found")

								 cannot find resource specified by .spec.identityProviders[2].objectRef (with name "also will not be found")`,
							)},
						{
							Type: "IdentityProvidersObjectRefAPIGroupSuffixValid", Status: "False", Reason: "APIGroupUnrecognized",
							Message: fmt.Sprintf(`some API groups specified by .spec.identityProviders[].objectRef.apiGroup are not recognized `+
								`(should be "idp.supervisor.%s"): "this is the wrong api group"`, env.APIGroupSuffix),
						},
						{
							Type: "IdentityProvidersObjectRefKindValid", Status: "False", Reason: "KindUnrecognized",
							Message: `some kinds specified by .spec.identityProviders[].objectRef.kind are not recognized ` +
								`(should be one of "ActiveDirectoryIdentityProvider", "GitHubIdentityProvider", "LDAPIdentityProvider", "OIDCIdentityProvider"): "this is the wrong kind"`,
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
						{
							Type: "TransformsExamplesPassed", Status: "False", Reason: "TransformsExamplesFailed",
							Message: here.Doc(
								`unable to check if the examples specified by .spec.identityProviders[0].transforms.examples[] had errors because an expression was invalid

								 .spec.identityProviders[2].transforms.examples[2] example failed:
								 expected: authentication to be rejected
								 actual:   authentication was not rejected

								 .spec.identityProviders[2].transforms.examples[3] example failed:
								 expected: authentication not to be rejected
								 actual:   authentication was rejected with message "only special users allowed"

								 .spec.identityProviders[2].transforms.examples[4] example failed:
								 expected: authentication rejection message "wrong message"
								 actual:   authentication rejection message "only special users allowed"

								 .spec.identityProviders[2].transforms.examples[6] example failed:
								 expected: username "wrong"
								 actual:   username "pre:ryan"

								 .spec.identityProviders[2].transforms.examples[6] example failed:
								 expected: groups []
								 actual:   groups ["pre:a", "pre:b"]

								 .spec.identityProviders[2].transforms.examples[7] example failed:
								 expected: username "wrong"
								 actual:   username "pre:ryan"

								 .spec.identityProviders[2].transforms.examples[8] example failed:
								 expected: groups ["wrong1", "wrong2"]
								 actual:   groups ["pre:a", "pre:b"]

								 .spec.identityProviders[2].transforms.examples[9] example failed:
								 expected: username ""
								 actual:   username "pre:ryan"

								 .spec.identityProviders[2].transforms.examples[9] example failed:
								 expected: groups []
								 actual:   groups ["pre:a", "pre:b"]`,
							),
						},
						{
							Type: "TransformsExpressionsValid", Status: "False", Reason: "InvalidTransformsExpressions",
							Message: here.Doc(
								`spec.identityProvider[0].transforms.expressions[0].expression was invalid:
								 CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'is' expecting <EOF>
								  | this is not a valid cel expression
								  | .....^

								 spec.identityProvider[0].transforms.expressions[1].expression was invalid:
								 CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'is' expecting <EOF>
								  | this is also not a valid cel expression
								  | .....^

								 spec.identityProvider[0].transforms.expressions[3].expression was invalid:
								 CEL expression compile error: ERROR: <input>:1:7: Syntax error: mismatched input 'not' expecting <EOF>
								  | still not a valid cel expression
								  | ......^`,
							),
						},
					},
				))

				// Updating the FederationDomain to fix some of the problems should make some of the errors go away.
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					gotFD, err := federationDomainsClient.Get(ctx, fd.Name, metav1.GetOptions{})
					require.NoError(t, err)

					gotFD.Spec.IdentityProviders[0] = supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						// Fix the display name.
						DisplayName: "now made unique",
						// Fix the objectRef.
						ObjectRef: corev1.TypedLocalObjectReference{
							APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
							Kind:     "OIDCIdentityProvider",
							Name:     oidcIdentityProvider.Name,
						},
						Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
							Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
								{Name: "foo", Type: "string", StringValue: "bar"},
							},
							Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
								// Fix the compile errors.
								{Type: "username/v1", Expression: `"pre:" + username`},
							},
							Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
								{ // this example should fail because it expects both the wrong username and groups
									Username: "ryan",
									Groups:   []string{"b", "a"},
									Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
										Username: "wrong",
										Groups:   []string{},
										Rejected: false,
									},
								},
							},
						},
					}

					gotFD.Spec.IdentityProviders[2].Transforms.Examples = []supervisorconfigv1alpha1.FederationDomainTransformsExample{
						{ // this example should pass
							Username: "other",
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Rejected: true,
								Message:  "only special users allowed",
							},
						},
					}

					_, updateErr := federationDomainsClient.Update(ctx, gotFD, metav1.UpdateOptions{})
					return updateErr
				})
				require.NoError(t, err)

				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, replaceSomeConditions(t,
					allSuccessfulFederationDomainConditions(fd.Spec),
					[]metav1.Condition{
						{
							Type: "IdentityProvidersFound", Status: "False", Reason: "IdentityProvidersObjectRefsNotFound",
							Message: `cannot find resource specified by .spec.identityProviders[2].objectRef (with name "also will not be found")`,
						},
						{
							Type: "IdentityProvidersObjectRefKindValid", Status: "False", Reason: "KindUnrecognized",
							Message: `some kinds specified by .spec.identityProviders[].objectRef.kind are not recognized ` +
								`(should be one of "ActiveDirectoryIdentityProvider", "GitHubIdentityProvider", "LDAPIdentityProvider", "OIDCIdentityProvider"): "this is the wrong kind"`,
						},
						{
							Type: "Ready", Status: "False", Reason: "NotReady",
							Message: "the FederationDomain is not ready: see other conditions for details",
						},
						{
							Type: "TransformsExamplesPassed", Status: "False", Reason: "TransformsExamplesFailed",
							Message: here.Doc(
								`.spec.identityProviders[0].transforms.examples[0] example failed:
								 expected: username "wrong"
								 actual:   username "pre:ryan"

								 .spec.identityProviders[0].transforms.examples[0] example failed:
								 expected: groups []
								 actual:   groups ["a", "b"]`,
							),
						},
					},
				))

				// Updating the FederationDomain to fix the rest of the problems should make all the errors go away.
				err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
					gotFD, err := federationDomainsClient.Get(ctx, fd.Name, metav1.GetOptions{})
					require.NoError(t, err)

					gotFD.Spec.IdentityProviders[2].ObjectRef = corev1.TypedLocalObjectReference{
						APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
						Kind:     "OIDCIdentityProvider",
						Name:     oidcIdentityProvider.Name,
					}

					gotFD.Spec.IdentityProviders[0].Transforms.Examples = []supervisorconfigv1alpha1.FederationDomainTransformsExample{
						{ // this example should pass
							Username: "ryan",
							Groups:   []string{"b", "a"},
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Username: "pre:ryan",
								Groups:   []string{"a", "b"},
							},
						},
					}

					_, updateErr := federationDomainsClient.Update(ctx, gotFD, metav1.UpdateOptions{})
					return updateErr
				})
				require.NoError(t, err)

				testlib.WaitForFederationDomainStatusPhase(ctx, t, fd.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
				testlib.WaitForFederationDomainStatusConditions(ctx, t, fd.Name, allSuccessfulFederationDomainConditions(fd.Spec))
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

func TestSupervisorFederationDomainCRDValidations_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	fdClient := testlib.NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(env.SupervisorNamespace)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	adminClient := testlib.NewKubernetesClientset(t)
	usingKubeVersionInCluster23OrOlder := testutil.KubeServerMinorVersionInBetweenInclusive(t, adminClient.Discovery(), 0, 23)
	usingKubeVersionInCluster24Through31Inclusive := testutil.KubeServerMinorVersionInBetweenInclusive(t, adminClient.Discovery(), 24, 31)
	usingKubeVersionInCluster32OrNewer := !usingKubeVersionInCluster23OrOlder && !usingKubeVersionInCluster24Through31Inclusive

	objectMeta := testlib.ObjectMetaWithRandomName(t, "federation-domain")

	tests := []struct {
		name     string
		fd       *supervisorconfigv1alpha1.FederationDomain
		wantErrs []string

		// optionally override wantErr for one or more specific versions of Kube, due to changing validation error text
		wantKube23OrOlderErrs            []string
		wantKube24Through31InclusiveErrs []string
		wantKube32OrNewerErrs            []string
	}{
		{
			name: "issuer cannot be empty",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "",
				},
			},
			wantErrs: []string{`spec.issuer: Invalid value: "": spec.issuer in body should be at least 1 chars long`},
		},
		{
			name: "IDP display names cannot be empty",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].displayName: Invalid value: "": spec.identityProviders[0].displayName in body should be at least 1 chars long`},
		},
		{
			name: "IDP transform constants must have unique names",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "notUnique", Type: "string", StringValue: "foo"},
									{Name: "notUnique", Type: "string", StringValue: "bar"},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.constants[1]: Duplicate value: map[string]interface {}{"name":"notUnique"}`},
		},
		{
			name: "IDP transform constant names cannot be empty",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "", Type: "string"},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.constants[0].name: Invalid value: "": spec.identityProviders[0].transforms.constants[0].name in body should be at least 1 chars long`},
		},
		{
			name: "IDP transform constant names cannot be more than 64 characters",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "12345678901234567890123456789012345678901234567890123456789012345", Type: "string"},
								},
							},
						},
					},
				},
			},
			wantKube23OrOlderErrs:            []string{`spec.identityProviders.transforms.constants.name: Invalid value: "12345678901234567890123456789012345678901234567890123456789012345": spec.identityProviders.transforms.constants.name in body should be at most 64 chars long`},
			wantKube24Through31InclusiveErrs: []string{`spec.identityProviders[0].transforms.constants[0].name: Too long: may not be longer than 64`},
			wantKube32OrNewerErrs:            []string{`spec.identityProviders[0].transforms.constants[0].name: Too long: may not be more than 64 bytes`},
		},
		{
			name: "IDP transform constant names must be a legal CEL variable name",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "cannot have spaces", Type: "string"},
									{Name: "1mustStartWithLetter", Type: "string"},
									{Name: "_mustStartWithLetter", Type: "string"},
									{Name: "canOnlyIncludeLettersAndNumbersAnd_", Type: "string"},
									{Name: "CanStart1_withUpperCase", Type: "string"},
								},
							},
						},
					},
				},
			},
			wantKube23OrOlderErrs: []string{`spec.identityProviders.transforms.constants.name: Invalid value: "cannot have spaces": spec.identityProviders.transforms.constants.name in body should match '^[a-zA-Z][_a-zA-Z0-9]*$'`},
			wantErrs: []string{
				`spec.identityProviders[0].transforms.constants[0].name: Invalid value: "cannot have spaces": spec.identityProviders[0].transforms.constants[0].name in body should match '^[a-zA-Z][_a-zA-Z0-9]*$'`,
				`spec.identityProviders[0].transforms.constants[1].name: Invalid value: "1mustStartWithLetter": spec.identityProviders[0].transforms.constants[1].name in body should match '^[a-zA-Z][_a-zA-Z0-9]*$'`,
				`spec.identityProviders[0].transforms.constants[2].name: Invalid value: "_mustStartWithLetter": spec.identityProviders[0].transforms.constants[2].name in body should match '^[a-zA-Z][_a-zA-Z0-9]*$'`},
		},
		{
			name: "IDP transform constant types must be one of the allowed enum strings",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "a", Type: "this is invalid"},
									{Name: "b", Type: "string"},
									{Name: "c", Type: "stringList"},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.constants[0].type: Unsupported value: "this is invalid": supported values: "string", "stringList"`},
		},
		{
			name: "IDP transform expression types must be one of the allowed enum strings",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
									{Type: "this is invalid", Expression: "foo"},
									{Type: "policy/v1", Expression: "foo"},
									{Type: "username/v1", Expression: "foo"},
									{Type: "groups/v1", Expression: "foo"},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.expressions[0].type: Unsupported value: "this is invalid": supported values: "policy/v1", "username/v1", "groups/v1"`},
		},
		{
			name: "IDP transform expressions cannot be empty",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
									{Type: "username/v1", Expression: ""},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.expressions[0].expression: Invalid value: "": spec.identityProviders[0].transforms.expressions[0].expression in body should be at least 1 chars long`},
		},
		{
			name: "IDP transform example usernames cannot be empty",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: objectMeta,
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
									{Username: ""},
									{Username: "non-empty"},
								},
							},
						},
					},
				},
			},
			wantErrs: []string{`spec.identityProviders[0].transforms.examples[0].username: Invalid value: "": spec.identityProviders[0].transforms.examples[0].username in body should be at least 1 chars long`},
		},
		{
			name: "minimum valid",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "fd"),
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
				},
			},
		},
		{
			name: "minimum valid when IDPs are included",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "fd"),
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
						},
					},
				},
			},
		},
		{
			name: "minimum valid when IDP has transform constants, expressions, and examples",
			fd: &supervisorconfigv1alpha1.FederationDomain{
				ObjectMeta: testlib.ObjectMetaWithRandomName(t, "fd"),
				Spec: supervisorconfigv1alpha1.FederationDomainSpec{
					Issuer: "https://example.com",
					IdentityProviders: []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
						{
							DisplayName: "foo",
							ObjectRef: corev1.TypedLocalObjectReference{
								APIGroup: ptr.To("required in older versions of Kubernetes for each item in the identityProviders slice"),
							},
							Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
								Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
									{Name: "foo", Type: "string"},
								},
								Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
									{Type: "username/v1", Expression: "foo"},
								},
								Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
									{Username: "foo"},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, actualCreateErr := fdClient.Create(ctx, tt.fd, metav1.CreateOptions{})

			t.Cleanup(func() {
				// Delete it if it exists.
				delErr := fdClient.Delete(ctx, tt.fd.Name, metav1.DeleteOptions{})
				if !apierrors.IsNotFound(delErr) {
					require.NoError(t, delErr)
				}
			})

			if len(tt.wantErrs) > 0 && len(tt.wantKube23OrOlderErrs) > 0 && len(tt.wantKube24Through31InclusiveErrs) > 0 && len(tt.wantKube32OrNewerErrs) > 0 {
				require.Fail(t, "test setup problem: wanted every possible kind of error, which would cause tt.wantErr to be unused")
			}

			if len(tt.wantErrs) == 0 && len(tt.wantKube23OrOlderErrs) == 0 && len(tt.wantKube24Through31InclusiveErrs) == 0 && len(tt.wantKube32OrNewerErrs) == 0 { //nolint:nestif
				// Did not want any error.
				require.NoError(t, actualCreateErr)
			} else {
				wantErr := tt.wantErrs
				if usingKubeVersionInCluster23OrOlder {
					// Old versions of Kubernetes did not show the index where the error occurred in some of the messages,
					// so remove the indices from the expected messages when running against an old version of Kube.
					// For the above tests, it should be enough to assume that there will only be indices up to 10.
					// This is useful when the only difference in the message between old and new is the missing indices.
					// Otherwise, use wantKube23OrOlderErr to say what the expected message should be for old versions.
					for i := range wantErr {
						for j := range 10 {
							wantErr[i] = strings.ReplaceAll(wantErr[i], fmt.Sprintf("[%d]", j), "")
						}
					}
				}
				if usingKubeVersionInCluster23OrOlder && len(tt.wantKube23OrOlderErrs) > 0 {
					// Sometimes there are other difference in older Kubernetes messages, so also allow exact
					// expectation strings for those cases in wantKube23OrOlderErr. When provided, use it on these Kube clusters.
					wantErr = tt.wantKube23OrOlderErrs
				}
				if usingKubeVersionInCluster24Through31Inclusive && len(tt.wantKube24Through31InclusiveErrs) > 0 {
					// Also allow overriding with an exact expected error for these Kube versions.
					wantErr = tt.wantKube24Through31InclusiveErrs
				}
				if usingKubeVersionInCluster32OrNewer && len(tt.wantKube32OrNewerErrs) > 0 {
					// Also allow overriding with an exact expected error for these Kube versions.
					wantErr = tt.wantKube32OrNewerErrs
				}

				wantErrStr := fmt.Sprintf("FederationDomain.config.supervisor.%s %q is invalid: ",
					env.APIGroupSuffix, objectMeta.Name)

				if len(wantErr) == 1 {
					wantErrStr += wantErr[0]
				} else {
					wantErrStr += "[" + strings.Join(wantErr, ", ") + "]"
				}

				require.EqualError(t, actualCreateErr, wantErrStr)
			}
		})
	}
}

func replaceSomeConditions(t *testing.T, conditions []metav1.Condition, replaceWithTheseConditions []metav1.Condition) []metav1.Condition {
	cp := make([]metav1.Condition, len(conditions))
	copy(cp, conditions)
	for _, replacementCond := range replaceWithTheseConditions {
		found := false
		for i, cond := range cp {
			if replacementCond.Type == cond.Type {
				cp[i] = replacementCond
				found = true
				break
			}
		}
		if !found {
			require.Failf(t,
				"test setup problem",
				"replaceSomeConditions() helper was called to replace condition of type %q but no such condition was found in conditions slice",
				replacementCond.Type)
		}
	}
	return cp
}

func allSuccessfulLegacyFederationDomainConditions(t *testing.T, idpName string, federationDomainSpec supervisorconfigv1alpha1.FederationDomainSpec) []metav1.Condition {
	return replaceSomeConditions(t,
		allSuccessfulFederationDomainConditions(federationDomainSpec),
		[]metav1.Condition{
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

func allSuccessfulFederationDomainConditions(federationDomainSpec supervisorconfigv1alpha1.FederationDomainSpec) []metav1.Condition {
	return []metav1.Condition{
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
			Type: "TransformsExamplesPassed", Status: "True", Reason: "Success",
			Message: "the examples specified by .spec.identityProviders[].transforms.examples[] had no errors",
		},
		{
			Type: "TransformsExpressionsValid", Status: "True", Reason: "Success",
			Message: "the expressions specified by .spec.identityProviders[].transforms.expressions[] are valid",
		},
	}
}
