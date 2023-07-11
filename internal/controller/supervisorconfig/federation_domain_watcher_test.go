// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/pointer"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/idtransform"
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

var federationDomainGVR = schema.GroupVersionResource{
	Group:    configv1alpha1.SchemeGroupVersion.Group,
	Version:  configv1alpha1.SchemeGroupVersion.Version,
	Resource: "federationdomains",
}

func TestTestFederationDomainWatcherControllerSync(t *testing.T) {
	t.Parallel()

	const namespace = "some-namespace"
	const apiGroupSupervisor = "idp.supervisor.pinniped.dev"

	frozenNow := time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)
	frozenMetav1Now := metav1.NewTime(frozenNow)

	oidcIdentityProvider := &idpv1alpha1.OIDCIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-oidc-idp",
			Namespace: namespace,
			UID:       "some-oidc-uid",
		},
	}

	ldapIdentityProvider := &idpv1alpha1.LDAPIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-ldap-idp",
			Namespace: namespace,
			UID:       "some-ldap-uid",
		},
	}

	adIdentityProvider := &idpv1alpha1.ActiveDirectoryIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-ad-idp",
			Namespace: namespace,
			UID:       "some-ad-uid",
		},
	}

	federationDomain1 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer1.com"},
	}

	federationDomain2 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer2.com"},
	}

	invalidIssuerURLFederationDomain := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://invalid-issuer.com?some=query"},
	}

	federationDomainIssuerWithIDPs := func(t *testing.T, fedDomainIssuer string, fdIDPs []*federationdomainproviders.FederationDomainIdentityProvider) *federationdomainproviders.FederationDomainIssuer {
		fdIssuer, err := federationdomainproviders.NewFederationDomainIssuer(fedDomainIssuer, fdIDPs)
		require.NoError(t, err)
		return fdIssuer
	}

	federationDomainIssuerWithDefaultIDP := func(t *testing.T, fedDomainIssuer string, idpObjectMeta metav1.ObjectMeta) *federationdomainproviders.FederationDomainIssuer {
		fdIDP := &federationdomainproviders.FederationDomainIdentityProvider{
			DisplayName: idpObjectMeta.Name,
			UID:         idpObjectMeta.UID,
			Transforms:  idtransform.NewTransformationPipeline(),
		}
		fdIssuer, err := federationdomainproviders.NewFederationDomainIssuerWithDefaultIDP(fedDomainIssuer, fdIDP)
		require.NoError(t, err)
		return fdIssuer
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

	happyIdentityProvidersFoundConditionLegacyConfigurationSuccess := func(idpName string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "LegacyConfigurationSuccess",
			Message: fmt.Sprintf("no resources were specified by .spec.identityProviders[].objectRef but exactly one "+
				"identity provider resource has been found: using %q as "+
				"identity provider: please explicitly list identity providers in .spec.identityProviders "+
				"(this legacy configuration mode may be removed in a future version of Pinniped)", idpName),
		}
	}

	happyIdentityProvidersFoundConditionSuccess := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the resources specified by .spec.identityProviders[].objectRef were found",
		}
	}

	sadIdentityProvidersFoundConditionLegacyConfigurationIdentityProviderNotFound := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "LegacyConfigurationIdentityProviderNotFound",
			Message: "no resources were specified by .spec.identityProviders[].objectRef and no identity provider " +
				"resources have been found: please create an identity provider resource",
		}
	}

	sadIdentityProvidersFoundConditionIdentityProviderNotSpecified := func(idpCRsCount int, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "IdentityProviderNotSpecified",
			Message: fmt.Sprintf("no resources were specified by .spec.identityProviders[].objectRef "+
				"and %q identity provider resources have been found: "+
				"please update .spec.identityProviders to specify which identity providers "+
				"this federation domain should use", idpCRsCount),
		}
	}

	sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound := func(msg string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "IdentityProvidersObjectRefsNotFound",
			Message:            msg,
		}
	}

	allHappyConditionsLegacyConfigurationSuccess := func(issuer string, idpName string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return []configv1alpha1.Condition{
			// expect them to be sorted alphabetically by type
			happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(idpName, time, observedGeneration),
			happyIssuerIsUniqueCondition(time, observedGeneration),
			happyIssuerURLValidCondition(time, observedGeneration),
			happyOneTLSSecretPerIssuerHostnameCondition(time, observedGeneration),
			happyReadyCondition(issuer, time, observedGeneration),
		}
	}

	allHappyConditionsSuccess := func(issuer string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return []configv1alpha1.Condition{
			// expect them to be sorted alphabetically by type
			happyIdentityProvidersFoundConditionSuccess(frozenMetav1Now, 123),
			happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
			happyIssuerURLValidCondition(frozenMetav1Now, 123),
			happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
			happyReadyCondition(issuer, frozenMetav1Now, 123),
		}
	}

	invalidIssuerURL := ":/host//path"
	_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
	require.Error(t, err)

	tests := []struct {
		name              string
		inputObjects      []runtime.Object
		configClient      func(*pinnipedfake.Clientset)
		wantErr           string
		wantStatusUpdates []*configv1alpha1.FederationDomain
		wantFDIssuers     []*federationdomainproviders.FederationDomainIssuer
	}{
		{
			name:          "when there are no FederationDomains, no update actions happen and the list of FederationDomainIssuers is set to the empty list",
			inputObjects:  []runtime.Object{},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{},
		},
		{
			name: "legacy config: when no identity provider is specified on federation domains, but exactly one identity " +
				"provider resource exists on cluster, the controller will set a default IDP on each federation domain " +
				"matching the only identity provider found",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				oidcIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are two valid FederationDomains, but one is already up to date, the sync loop only updates " +
				"the out-of-date FederationDomain",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: federationDomain1.Name, Namespace: federationDomain1.Namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: federationDomain1.Spec.Issuer},
					Status: configv1alpha1.FederationDomainStatus{
						Phase:      configv1alpha1.FederationDomainPhaseReady,
						Conditions: allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
					},
				},
				federationDomain2,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				// only one update, because the other FederationDomain already had the right status
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are two valid FederationDomains, but updating one fails, the status on the FederationDomain will not change",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				oidcIdentityProvider,
			},
			configClient: func(client *pinnipedfake.Clientset) {
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
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are both valid and invalid FederationDomains, the status will be correctly set on each " +
				"FederationDomain individually",
			inputObjects: []runtime.Object{
				invalidIssuerURLFederationDomain,
				federationDomain2,
				oidcIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				// only the valid FederationDomain
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(invalidIssuerURLFederationDomain,
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are both valid and invalid FederationDomains, but updating the invalid one fails, the " +
				"existing status will be unchanged",
			inputObjects: []runtime.Object{
				invalidIssuerURLFederationDomain,
				federationDomain2,
				oidcIdentityProvider,
			},
			configClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor(
					"update",
					"federationdomains",
					func(action coretesting.Action) (bool, runtime.Object, error) {
						fd := action.(coretesting.UpdateAction).GetObject().(*configv1alpha1.FederationDomain)
						if fd.Name == invalidIssuerURLFederationDomain.Name {
							return true, nil, errors.New("some update error")
						}
						return false, nil, nil
					},
				)
			},
			wantErr: "could not update status: some update error",
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				// only the valid FederationDomain
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(invalidIssuerURLFederationDomain,
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are FederationDomains with duplicate issuer strings these particular FederationDomains " +
				"will report error on IssuerUnique conditions",
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
				oidcIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, "https://issuer-duplicate.com/A", oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess("https://issuer-duplicate.com/A", oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "when there are FederationDomains with the same issuer DNS hostname using different secretNames these " +
				"particular FederationDomains will report errors on OneTLSSecretPerIssuerHostname conditions",
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
				oidcIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, "https://issuer-not-duplicate.com", oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(oidcIdentityProvider.Name, frozenMetav1Now, 123),
						unknownIssuerIsUniqueCondition(frozenMetav1Now, 123),
						sadIssuerURLValidConditionCannotParse(frozenMetav1Now, 123),
						unknownOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess("https://issuer-not-duplicate.com", oidcIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "legacy config: no identity provider specified in federation domain and no identity providers found results in not found status",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						sadIdentityProvidersFoundConditionLegacyConfigurationIdentityProviderNotFound(frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						sadIdentityProvidersFoundConditionLegacyConfigurationIdentityProviderNotFound(frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
			},
		},
		{
			name: "legacy config: no identity provider specified in federation domain and multiple identity providers found results in not specified status",
			inputObjects: []runtime.Object{
				federationDomain1,
				oidcIdentityProvider,
				ldapIdentityProvider,
				adIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						sadIdentityProvidersFoundConditionIdentityProviderNotSpecified(3, frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
			},
		},
		{
			name: "the federation domain specifies identity providers that cannot be found",
			inputObjects: []runtime.Object{
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "cant-find-me",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     "cant-find-me-name",
								},
							},
							{
								DisplayName: "cant-find-me-either",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     "cant-find-me-either-name",
								},
							},
							{
								DisplayName: "cant-find-me-still",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "ActiveDirectoryIdentityProvider",
									Name:     "cant-find-me-still-name",
								},
							},
						},
					},
				},
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					[]configv1alpha1.Condition{
						sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound(
							`.spec.identityProviders[].objectRef identifies resource(s) that cannot be found: `+
								`.spec.identityProviders[0] with displayName "cant-find-me", `+
								`.spec.identityProviders[1] with displayName "cant-find-me-either", `+
								`.spec.identityProviders[2] with displayName "cant-find-me-still"`,
							frozenMetav1Now, 123),
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						happyIssuerURLValidCondition(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					},
				),
			},
		},
		{
			name: "the federation domain specifies identity providers that all exist",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				ldapIdentityProvider,
				adIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "can-find-me",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
							},
							{
								DisplayName: "can-find-me-too",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "can-find-me-three",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "ActiveDirectoryIdentityProvider",
									Name:     adIdentityProvider.Name,
								},
							},
						},
					},
				},
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithIDPs(t, "https://issuer1.com",
					[]*federationdomainproviders.FederationDomainIdentityProvider{
						{
							DisplayName: "can-find-me",
							UID:         oidcIdentityProvider.UID,
							Transforms:  idtransform.NewTransformationPipeline(),
						},
						{
							DisplayName: "can-find-me-too",
							UID:         ldapIdentityProvider.UID,
							Transforms:  idtransform.NewTransformationPipeline(),
						},
						{
							DisplayName: "can-find-me-three",
							UID:         adIdentityProvider.UID,
							Transforms:  idtransform.NewTransformationPipeline(),
						},
					}),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "the federation domain specifies illegal const type, which shouldn't really happen since the CRD validates it",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "can-find-me",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Constants: []configv1alpha1.FederationDomainTransformsConstant{
										{
											Type: "this is illegal",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: `one of spec.identityProvider[].transforms.constants[].type is invalid: "this is illegal"`,
		},
		{
			name: "the federation domain specifies illegal expression type, which shouldn't really happen since the CRD validates it",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "can-find-me",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{
											Type: "this is illegal",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: `one of spec.identityProvider[].transforms.expressions[].type is invalid: "this is illegal"`,
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
			if tt.configClient != nil {
				tt.configClient(pinnipedAPIClient)
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

			if tt.wantFDIssuers != nil {
				require.True(t, federationDomainsSetter.SetFederationDomainsWasCalled)
				require.ElementsMatch(t, tt.wantFDIssuers, federationDomainsSetter.FederationDomainsReceived)
			} else {
				require.False(t, federationDomainsSetter.SetFederationDomainsWasCalled)
			}

			if tt.wantStatusUpdates != nil {
				// This controller should only perform updates to FederationDomain statuses.
				// In this controller we don't actually care about the order of the actions, since the FederationDomains
				// statuses can be updated in any order.  Therefore, we are sorting here so we can use require.Equal
				// to make the test output easier to read. Unfortunately the timezone nested in the condition can still
				// make the test failure diffs ugly sometimes, but we do want to assert about timestamps so there's not
				// much we can do about those.
				actualFederationDomainUpdates := getFederationDomainStatusUpdates(t, pinnipedAPIClient.Actions())
				sortFederationDomainsByName(actualFederationDomainUpdates)
				sortFederationDomainsByName(tt.wantStatusUpdates)
				// Use require.Equal instead of require.ElementsMatch because require.Equal prints a nice diff.
				require.Equal(t, tt.wantStatusUpdates, actualFederationDomainUpdates)
			} else {
				require.Empty(t, pinnipedAPIClient.Actions())
			}
		})
	}
}

func expectedFederationDomainStatusUpdate(
	fd *configv1alpha1.FederationDomain,
	phase configv1alpha1.FederationDomainPhase,
	conditions []configv1alpha1.Condition,
) *configv1alpha1.FederationDomain {
	fdCopy := fd.DeepCopy()

	// We don't care about the spec of a FederationDomain in an update status action,
	// so clear it out to make it easier to write expected values.
	fdCopy.Spec = configv1alpha1.FederationDomainSpec{}

	fdCopy.Status.Phase = phase
	fdCopy.Status.Conditions = conditions

	return fdCopy
}

func getFederationDomainStatusUpdates(t *testing.T, actions []coretesting.Action) []*configv1alpha1.FederationDomain {
	federationDomains := []*configv1alpha1.FederationDomain{}

	for _, action := range actions {
		updateAction, ok := action.(coretesting.UpdateAction)
		require.True(t, ok, "failed to cast an action as an coretesting.UpdateAction: %#v", action)
		require.Equal(t, federationDomainGVR, updateAction.GetResource(), "an update action should have updated a FederationDomain but updated something else")
		require.Equal(t, "status", updateAction.GetSubresource(), "an update action should have updated the status subresource but updated something else")

		fd, ok := updateAction.GetObject().(*configv1alpha1.FederationDomain)
		require.True(t, ok, "failed to cast an action's object as a FederationDomain: %#v", updateAction.GetObject())
		require.Equal(t, fd.Namespace, updateAction.GetNamespace(), "an update action might have been called on the wrong namespace for a FederationDomain")

		// We don't care about the spec of a FederationDomain in an update status action,
		// so clear it out to make it easier to write expected values.
		copyOfFD := fd.DeepCopy()
		copyOfFD.Spec = configv1alpha1.FederationDomainSpec{}

		federationDomains = append(federationDomains, copyOfFD)
	}

	return federationDomains
}

func sortFederationDomainsByName(federationDomains []*configv1alpha1.FederationDomain) {
	sort.SliceStable(federationDomains, func(a, b int) bool {
		return federationDomains[a].GetName() < federationDomains[b].GetName()
	})
}
