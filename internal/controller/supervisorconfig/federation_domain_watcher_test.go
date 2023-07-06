// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/testutil"
)

func TestFederationDomainWatcherControllerInformerFilters(t *testing.T) {
	t.Parallel()

	federationDomainInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).Config().V1alpha1().FederationDomains()
	oidcIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().OIDCIdentityProviders()
	ldapIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().LDAPIdentityProviders()
	adIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().ActiveDirectoryIdentityProviders()

	tests := []struct {
		name       string
		obj        metav1.Object
		informer   controllerlib.InformerGetter
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "any FederationDomain changes",
			obj:        &configv1alpha1.FederationDomain{},
			informer:   federationDomainInformer,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name:       "any OIDCIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.OIDCIdentityProvider{},
			informer:   oidcIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
		{
			name:       "any LDAPIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.LDAPIdentityProvider{},
			informer:   ldapIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
		{
			name:       "any ActiveDirectoryIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.ActiveDirectoryIdentityProvider{},
			informer:   adIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			withInformer := testutil.NewObservableWithInformerOption()

			NewFederationDomainWatcherController(
				nil,
				nil,
				nil,
				federationDomainInformer,
				oidcIdentityProviderInformer,
				ldapIdentityProviderInformer,
				adIdentityProviderInformer,
				withInformer.WithInformer, // make it possible to observe the behavior of the Filters
			)

			unrelatedObj := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(test.informer)
			require.Equal(t, test.wantAdd, filter.Add(test.obj))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelatedObj, test.obj))
			require.Equal(t, test.wantUpdate, filter.Update(test.obj, &unrelatedObj))
			require.Equal(t, test.wantDelete, filter.Delete(test.obj))
		})
	}
}

type fakeFederationDomainsSetter struct {
	SetFederationDomainsWasCalled bool
	FederationDomainsReceived     []*federationdomainproviders.FederationDomainIssuer
}

func (f *fakeFederationDomainsSetter) SetFederationDomains(federationDomains ...*federationdomainproviders.FederationDomainIssuer) {
	f.SetFederationDomainsWasCalled = true
	f.FederationDomainsReceived = federationDomains
}

func TestTestFederationDomainWatcherControllerSync(t *testing.T) {
	t.Parallel()

	const namespace = "some-namespace"

	frozenNow := time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)
	frozenMetav1Now := metav1.NewTime(frozenNow)

	federationDomainGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "federationdomains",
	}

	federationDomain1 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer1.com"},
	}

	federationDomain1Issuer, err := federationdomainproviders.NewFederationDomainIssuer(
		federationDomain1.Spec.Issuer,
		[]*federationdomainproviders.FederationDomainIdentityProvider{},
	)
	require.NoError(t, err)

	federationDomain2 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer2.com"},
	}

	federationDomain2Issuer, err := federationdomainproviders.NewFederationDomainIssuer(
		federationDomain2.Spec.Issuer,
		[]*federationdomainproviders.FederationDomainIdentityProvider{},
	)
	require.NoError(t, err)

	invalidFederationDomain := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://invalid-issuer.com?some=query"},
	}

	happyReadyCondition := func(issuer string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "Ready",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message: fmt.Sprintf("the FederationDomain is ready and its endpoints are available: "+
				"the discovery endpoint is %s/.well-known/openid-configuration", issuer),
		}
	}

	sadReadyCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "Ready",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "NotReady",
			Message:            "the FederationDomain is not ready: see other conditions for details",
		}
	}

	happyIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.issuer is unique among all FederationDomains",
		}
	}

	unknownIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to check if spec.issuer is unique among all FederationDomains because URL cannot be parsed",
		}
	}

	sadIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DuplicateIssuer",
			Message:            "multiple FederationDomains have the same spec.issuer URL: these URLs must be unique (can use different hosts or paths)",
		}
	}

	happyOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL",
		}
	}

	unknownOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to check if all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL because URL cannot be parsed",
		}
	}

	sadOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DifferentSecretRefsFound",
			Message:            "when different FederationDomains are using the same hostname in the spec.issuer URL then they must also use the same TLS secretRef: different secretRefs found",
		}
	}

	happyIssuerURLValidCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.issuer is a valid URL",
		}
	}

	sadIssuerURLValidConditionCannotHaveQuery := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURL",
			Message:            "issuer must not have query",
		}
	}

	sadIssuerURLValidConditionCannotParse := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURL",
			Message:            `could not parse issuer as URL: parse ":/host//path": missing protocol scheme`,
		}
	}

	allHappyConditions := func(issuer string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return []configv1alpha1.Condition{
			happyIssuerIsUniqueCondition(time, observedGeneration),
			happyIssuerURLValidCondition(time, observedGeneration),
			happyOneTLSSecretPerIssuerHostnameCondition(time, observedGeneration),
			happyReadyCondition(issuer, time, observedGeneration),
		}
	}

	invalidIssuerURL := ":/host//path"
	_, err = url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
	require.Error(t, err)

	newCopyWithStatus := func(
		fd *configv1alpha1.FederationDomain,
		phase configv1alpha1.FederationDomainPhase,
		conditions []configv1alpha1.Condition,
	) *configv1alpha1.FederationDomain {
		fdCopy := fd.DeepCopy()
		fdCopy.Status.Phase = phase
		fdCopy.Status.Conditions = conditions
		return fdCopy
	}

	tests := []struct {
		name                        string
		inputObjects                []runtime.Object
		configPinnipedClient        func(*pinnipedfake.Clientset)
		wantErr                     string
		wantActions                 func(t *testing.T) []coretesting.Action
		wantFederationDomainIssuers func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer
	}{
		{
			name:         "there are no FederationDomains",
			inputObjects: []runtime.Object{},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{}
			},
		},
		{
			name: "there are some valid FederationDomains in the informer",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomain1Issuer,
					federationDomain2Issuer,
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain1.Namespace,
						newCopyWithStatus(federationDomain1,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are two valid FederationDomains, but one is already up to date, so only updates the out-of-date FederationDomain",
			inputObjects: []runtime.Object{
				newCopyWithStatus(federationDomain1, configv1alpha1.FederationDomainPhaseReady,
					allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123),
				),
				federationDomain2,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomain1Issuer,
					federationDomain2Issuer,
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are two valid FederationDomains, but updating one fails",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor(
					"update",
					"federationdomains",
					func(action coretesting.Action) (bool, runtime.Object, error) {
						fd := action.(coretesting.UpdateAction).GetObject().(*configv1alpha1.FederationDomain)
						if fd.Name == federationDomain1.Name {
							return true, nil, errors.New("some update error")
						}
						return false, nil, nil
					},
				)
			},
			wantErr: "could not update status: some update error",
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomain2Issuer, // federationDomain1 is not included because it encountered an error
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain1.Namespace,
						newCopyWithStatus(federationDomain1,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are both valid and invalid FederationDomains",
			inputObjects: []runtime.Object{
				invalidFederationDomain,
				federationDomain2,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomain2Issuer, // only the valid FederationDomain
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(invalidFederationDomain,
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are both valid and invalid FederationDomains, but updating the invalid one fails",
			inputObjects: []runtime.Object{
				invalidFederationDomain,
				federationDomain2,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor(
					"update",
					"federationdomains",
					func(action coretesting.Action) (bool, runtime.Object, error) {
						fd := action.(coretesting.UpdateAction).GetObject().(*configv1alpha1.FederationDomain)
						if fd.Name == invalidFederationDomain.Name {
							return true, nil, errors.New("some update error")
						}
						return false, nil, nil
					},
				)
			},
			wantErr: "could not update status: some update error",
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomain2Issuer, // only the valid FederationDomain
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(invalidFederationDomain,
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are FederationDomains with duplicate issuer names",
			inputObjects: []runtime.Object{
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path (paths are case-sensitive)
				},
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				fdi, err := federationdomainproviders.NewFederationDomainIssuer(
					"https://issuer-duplicate.com/A",
					[]*federationdomainproviders.FederationDomainIdentityProvider{},
				)
				require.NoError(t, err)
				return []*federationdomainproviders.FederationDomainIssuer{
					fdi,
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"},
							},
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions("https://issuer-duplicate.com/A", frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "there are FederationDomains with the same issuer DNS hostname using different secretNames",
			inputObjects: []runtime.Object{
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						// Validation treats these as the same DNS hostname even though they have different port numbers,
						// because SNI information on the incoming requests is not going to include port numbers.
						Issuer: "https://issuer-duplicate-address.com:1234/path2",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer-not-duplicate.com",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: invalidIssuerURL,
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				fdi, err := federationdomainproviders.NewFederationDomainIssuer(
					"https://issuer-not-duplicate.com",
					[]*federationdomainproviders.FederationDomainIdentityProvider{},
				)
				require.NoError(t, err)
				return []*federationdomainproviders.FederationDomainIssuer{
					fdi,
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://issuer-duplicate-address.com:1234/path2",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: invalidIssuerURL,
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								unknownIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotParse(frozenMetav1Now, 123),
								unknownOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://issuer-not-duplicate.com",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditions("https://issuer-not-duplicate.com", frozenMetav1Now, 123),
						),
					),
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			federationDomainsSetter := &fakeFederationDomainsSetter{}
			pinnipedAPIClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()
			for _, o := range tt.inputObjects {
				require.NoError(t, pinnipedAPIClient.Tracker().Add(o))
				require.NoError(t, pinnipedInformerClient.Tracker().Add(o))
			}
			if tt.configPinnipedClient != nil {
				tt.configPinnipedClient(pinnipedAPIClient)
			}
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)

			controller := NewFederationDomainWatcherController(
				federationDomainsSetter,
				clocktesting.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{Namespace: namespace, Name: "config-name"}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.wantActions != nil {
				require.ElementsMatch(t, tt.wantActions(t), pinnipedAPIClient.Actions())
			} else {
				require.Empty(t, pinnipedAPIClient.Actions())
			}

			if tt.wantFederationDomainIssuers != nil {
				require.True(t, federationDomainsSetter.SetFederationDomainsWasCalled)
				require.ElementsMatch(t, tt.wantFederationDomainIssuers(t), federationDomainsSetter.FederationDomainsReceived)
			} else {
				require.False(t, federationDomainsSetter.SetFederationDomainsWasCalled)
			}
		})
	}
}
