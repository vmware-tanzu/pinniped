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
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/pointer"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/here"
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
				"",
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
	const apiGroupSuffix = "custom.suffix.pinniped.dev"
	const apiGroupSupervisor = "idp.supervisor." + apiGroupSuffix

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

	sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound := func(idpsNotFound string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "IdentityProvidersObjectRefsNotFound",
			Message:            fmt.Sprintf(".spec.identityProviders[].objectRef identifies resource(s) that cannot be found: %s", idpsNotFound),
		}
	}

	happyDisplayNamesUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersDisplayNamesUnique",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the names specified by .spec.identityProviders[].displayName are unique",
		}
	}

	sadDisplayNamesUniqueCondition := func(duplicateNames string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersDisplayNamesUnique",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DuplicateDisplayNames",
			Message:            fmt.Sprintf("the names specified by .spec.identityProviders[].displayName contain duplicates: %s", duplicateNames),
		}
	}

	happyConstNamesUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsConstantsNamesUnique",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the names specified by .spec.identityProviders[].transforms.constants[].name are unique",
		}
	}

	sadConstNamesUniqueCondition := func(errorMessages string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsConstantsNamesUnique",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DuplicateConstantsNames",
			Message:            errorMessages,
		}
	}

	happyTransformationExpressionsCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsExpressionsValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the expressions specified by .spec.identityProviders[].transforms.expressions[] are valid",
		}
	}

	sadTransformationExpressionsCondition := func(errorMessages string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsExpressionsValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidTransformsExpressions",
			Message:            errorMessages,
		}
	}

	happyTransformationExamplesCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsExamplesPassed",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the examples specified by .spec.identityProviders[].transforms.examples[] had no errors",
		}
	}

	sadTransformationExamplesCondition := func(errorMessages string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "TransformsExamplesPassed",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "TransformsExamplesFailed",
			Message:            errorMessages,
		}
	}

	happyAPIGroupSuffixCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersObjectRefAPIGroupSuffixValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the API groups specified by .spec.identityProviders[].objectRef.apiGroup are recognized",
		}
	}

	sadAPIGroupSuffixCondition := func(badApiGroups string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersObjectRefAPIGroupSuffixValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "APIGroupUnrecognized",
			Message: fmt.Sprintf("the API groups specified by .spec.identityProviders[].objectRef.apiGroup "+
				"are not recognized (should be \"idp.supervisor.%s\"): %s", apiGroupSuffix, badApiGroups),
		}
	}

	happyKindCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersObjectRefKindValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the kinds specified by .spec.identityProviders[].objectRef.kind are recognized",
		}
	}

	sadKindCondition := func(badKinds string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersObjectRefKindValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "KindUnrecognized",
			Message: fmt.Sprintf(`the kinds specified by .spec.identityProviders[].objectRef.kind are `+
				`not recognized (should be one of "ActiveDirectoryIdentityProvider", "LDAPIdentityProvider", "OIDCIdentityProvider"): %s`, badKinds),
		}
	}

	sortConditionsByType := func(c []configv1alpha1.Condition) []configv1alpha1.Condition {
		cp := make([]configv1alpha1.Condition, len(c))
		copy(cp, c)
		sort.SliceStable(cp, func(i, j int) bool {
			return cp[i].Type < cp[j].Type
		})
		return cp
	}

	replaceConditions := func(conditions []configv1alpha1.Condition, sadConditions []configv1alpha1.Condition) []configv1alpha1.Condition {
		for _, sadReplaceCondition := range sadConditions {
			for origIndex, origCondition := range conditions {
				if origCondition.Type == sadReplaceCondition.Type {
					conditions[origIndex] = sadReplaceCondition
					break
				}
			}
		}
		return conditions
	}

	allHappyConditionsSuccess := func(issuer string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return sortConditionsByType([]configv1alpha1.Condition{
			happyTransformationExamplesCondition(frozenMetav1Now, 123),
			happyTransformationExpressionsCondition(frozenMetav1Now, 123),
			happyConstNamesUniqueCondition(frozenMetav1Now, 123),
			happyKindCondition(frozenMetav1Now, 123),
			happyAPIGroupSuffixCondition(frozenMetav1Now, 123),
			happyDisplayNamesUniqueCondition(frozenMetav1Now, 123),
			happyIdentityProvidersFoundConditionSuccess(frozenMetav1Now, 123),
			happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
			happyIssuerURLValidCondition(frozenMetav1Now, 123),
			happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
			happyReadyCondition(issuer, frozenMetav1Now, 123),
		})
	}

	allHappyConditionsLegacyConfigurationSuccess := func(issuer string, idpName string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return replaceConditions(
			allHappyConditionsSuccess(issuer, time, observedGeneration),
			[]configv1alpha1.Condition{
				happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(idpName, time, observedGeneration),
			},
		)
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
			name: "legacy config: when no identity provider is specified on federation domains, but exactly one OIDC identity " +
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
			name: "legacy config: when no identity provider is specified on federation domains, but exactly one LDAP identity " +
				"provider resource exists on cluster, the controller will set a default IDP on each federation domain " +
				"matching the only identity provider found",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				ldapIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, ldapIdentityProvider.ObjectMeta),
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, ldapIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, ldapIdentityProvider.Name, frozenMetav1Now, 123),
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, ldapIdentityProvider.Name, frozenMetav1Now, 123),
				),
			},
		},
		{
			name: "legacy config: when no identity provider is specified on federation domains, but exactly one AD identity " +
				"provider resource exists on cluster, the controller will set a default IDP on each federation domain " +
				"matching the only identity provider found",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				adIdentityProvider,
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, adIdentityProvider.ObjectMeta),
				federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, adIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, adIdentityProvider.Name, frozenMetav1Now, 123),
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, adIdentityProvider.Name, frozenMetav1Now, 123),
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
			name: "when the status of the FederationDomains is based on an old generation, it is updated",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: federationDomain1.Name, Namespace: federationDomain1.Namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: federationDomain1.Spec.Issuer},
					Status: configv1alpha1.FederationDomainStatus{
						Phase: configv1alpha1.FederationDomainPhaseReady,
						Conditions: allHappyConditionsLegacyConfigurationSuccess(
							federationDomain1.Spec.Issuer,
							oidcIdentityProvider.Name,
							frozenMetav1Now,
							2, // this is an older generation
						),
					},
				},
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, oidcIdentityProvider.ObjectMeta),
			},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				// only one update, because the other FederationDomain already had the right status
				expectedFederationDomainStatusUpdate(federationDomain1,
					configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(
						federationDomain1.Spec.Issuer,
						oidcIdentityProvider.Name,
						frozenMetav1Now,
						123, // all conditions are updated to the new observed generation
					),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess("https://iSSueR-duPlicAte.cOm/a", oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess("https://issuer-duplicate.com/a", oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess("https://iSSueR-duPlicAte-adDress.cOm/path1", oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess("https://issuer-duplicate-address.com:1234/path2", oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(invalidIssuerURL, oidcIdentityProvider.Name, frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							unknownIssuerIsUniqueCondition(frozenMetav1Now, 123),
							sadIssuerURLValidConditionCannotParse(frozenMetav1Now, 123),
							unknownOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, "", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIdentityProvidersFoundConditionLegacyConfigurationIdentityProviderNotFound(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
				expectedFederationDomainStatusUpdate(federationDomain2,
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, "", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIdentityProvidersFoundConditionLegacyConfigurationIdentityProviderNotFound(frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, "", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIdentityProvidersFoundConditionIdentityProviderNotSpecified(3, frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound(
								`.spec.identityProviders[0] with displayName "cant-find-me", `+
									`.spec.identityProviders[1] with displayName "cant-find-me-either", `+
									`.spec.identityProviders[2] with displayName "cant-find-me-still"`,
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
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
			name: "the federation domain has duplicate display names for IDPs",
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
								DisplayName: "duplicate1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
							},
							{
								DisplayName: "duplicate1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "duplicate1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "unique",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "ActiveDirectoryIdentityProvider",
									Name:     adIdentityProvider.Name,
								},
							},
							{
								DisplayName: "duplicate2",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "duplicate2",
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
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{},
			wantStatusUpdates: []*configv1alpha1.FederationDomain{
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadDisplayNamesUniqueCondition(`"duplicate1", "duplicate2"`, frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has unrecognized api group names in objectRefs",
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
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String("wrong.example.com"),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
							},
							{
								DisplayName: "name2",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(""), // empty string is wrong
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "name3",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: nil, // nil is wrong, and gets treated like an empty string in the error condition
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "name4",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor), // correct
									Kind:     "ActiveDirectoryIdentityProvider",
									Name:     adIdentityProvider.Name,
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadAPIGroupSuffixCondition(`"", "", "wrong.example.com"`, frozenMetav1Now, 123),
							sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound(
								`.spec.identityProviders[0] with displayName "name1", `+
									`.spec.identityProviders[1] with displayName "name2", `+
									`.spec.identityProviders[2] with displayName "name3"`,
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has unrecognized kind names in objectRefs",
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
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider", // correct
									Name:     oidcIdentityProvider.Name,
								},
							},
							{
								DisplayName: "name2",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "wrong",
									Name:     ldapIdentityProvider.Name,
								},
							},
							{
								DisplayName: "name3",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "", // empty is also wrong
									Name:     ldapIdentityProvider.Name,
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadKindCondition(`"", "wrong"`, frozenMetav1Now, 123),
							sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound(
								`.spec.identityProviders[1] with displayName "name2", `+
									`.spec.identityProviders[2] with displayName "name3"`,
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has duplicate transformation const names",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Constants: []configv1alpha1.FederationDomainTransformsConstant{
										{Name: "duplicate1", Type: "string", StringValue: "abc"},
										{Name: "duplicate1", Type: "stringList", StringListValue: []string{"def"}},
										{Name: "duplicate1", Type: "string", StringValue: "efg"},
										{Name: "duplicate2", Type: "string", StringValue: "123"},
										{Name: "duplicate2", Type: "string", StringValue: "456"},
										{Name: "uniqueName", Type: "string", StringValue: "hij"},
									},
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadConstNamesUniqueCondition(
								`the names specified by .spec.identityProviders[0].transforms.constants[].name contain duplicates: "duplicate1", "duplicate2"`,
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has transformation expressions which don't compile",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: "this is not a valid cel expression"},
										{Type: "groups/v1", Expression: "this is also not a valid cel expression"},
										{Type: "username/v1", Expression: "username"}, // valid
										{Type: "policy/v1", Expression: "still not a valid cel expression"},
									},
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadTransformationExpressionsCondition(here.Doc(
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
							), frozenMetav1Now, 123),
							sadTransformationExamplesCondition(
								"unable to check if the examples specified by .spec.identityProviders[0].transforms.examples[] had errors because an expression was invalid",
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has transformation examples which don't pass",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "policy/v1", Expression: `username == "ryan" || username == "rejectMeWithDefaultMessage"`, Message: "only ryan allowed"},
										{Type: "policy/v1", Expression: `username != "rejectMeWithDefaultMessage"`}, // no message specified
										{Type: "username/v1", Expression: `"pre:" + username`},
										{Type: "groups/v1", Expression: `groups.map(g, "pre:" + g)`},
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{ // this example should pass
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "pre:ryan",
												Groups:   []string{"pre:b", "pre:a", "pre:b", "pre:a"}, // order and repeats don't matter, treated like a set
												Rejected: false,
											},
										},
										{ // this example should pass
											Username: "other",
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												Message:  "only ryan allowed",
											},
										},
										{ // this example should fail because it expects the user to be rejected but the user was actually not rejected
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												Message:  "this input is ignored in this case",
											},
										},
										{ // this example should fail because it expects the user not to be rejected but they were actually rejected
											Username: "other",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "pre:other",
												Groups:   []string{"pre:a", "pre:b"},
												Rejected: false,
											},
										},
										{ // this example should fail because it expects the wrong rejection message
											Username: "other",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												Message:  "wrong message",
											},
										},
										{ // this example should pass even though it does not make any assertion about the rejection message
											// because the message assertions defaults to asserting the default rejection message
											Username: "rejectMeWithDefaultMessage",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
											},
										},
										{ // this example should fail because it expects both the wrong username and groups
											Username: "ryan",
											Groups:   []string{"b", "a"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "wrong",
												Groups:   []string{},
												Rejected: false,
											},
										},
										{ // this example should fail because it expects the wrong username only
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "wrong",
												Groups:   []string{"pre:b", "pre:a"},
												Rejected: false,
											},
										},
										{ // this example should fail because it expects the wrong groups only
											Username: "ryan",
											Groups:   []string{"b", "a"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "pre:ryan",
												Groups:   []string{"wrong2", "wrong1"},
												Rejected: false,
											},
										},
										{ // this example should fail because it does not expect anything but the auth actually was successful
											Username: "ryan",
											Groups:   []string{"b", "a"},
											Expects:  configv1alpha1.FederationDomainTransformsExampleExpects{},
										},
									},
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadTransformationExamplesCondition(here.Doc(
								`.spec.identityProviders[0].transforms.examples[2] example failed:
									expected: authentication to be rejected
									actual:   authentication was not rejected

									.spec.identityProviders[0].transforms.examples[3] example failed:
									expected: authentication not to be rejected
									actual:   authentication was rejected with message "only ryan allowed"

									.spec.identityProviders[0].transforms.examples[4] example failed:
									expected: authentication rejection message "wrong message"
									actual:   authentication rejection message "only ryan allowed"

									.spec.identityProviders[0].transforms.examples[6] example failed:
									expected: username "wrong"
									actual:   username "pre:ryan"

									.spec.identityProviders[0].transforms.examples[6] example failed:
									expected: groups []
									actual:   groups ["pre:a", "pre:b"]

									.spec.identityProviders[0].transforms.examples[7] example failed:
									expected: username "wrong"
									actual:   username "pre:ryan"

									.spec.identityProviders[0].transforms.examples[8] example failed:
									expected: groups ["wrong1", "wrong2"]
									actual:   groups ["pre:a", "pre:b"]

									.spec.identityProviders[0].transforms.examples[9] example failed:
									expected: username ""
									actual:   username "pre:ryan"

									.spec.identityProviders[0].transforms.examples[9] example failed:
									expected: groups []
									actual:   groups ["pre:a", "pre:b"]`,
							), frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has transformation expressions that return illegal values with examples which exercise them",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `username == "ryan" ? "" : username`}, // not allowed to return an empty string as the transformed username
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{ // every example which encounters an unexpected error should fail because the transformation pipeline returned an error
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects:  configv1alpha1.FederationDomainTransformsExampleExpects{},
										},
										{ // every example which encounters an unexpected error should fail because the transformation pipeline returned an error
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects:  configv1alpha1.FederationDomainTransformsExampleExpects{},
										},
										{ // this should pass
											Username: "other",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "other",
												Groups:   []string{"a", "b"},
												Rejected: false,
											},
										},
									},
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
					replaceConditions(
						allHappyConditionsSuccess("https://issuer1.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadTransformationExamplesCondition(here.Doc(
								`.spec.identityProviders[0].transforms.examples[0] example failed:
									expected: no transformation errors
									actual:   transformations resulted in an unexpected error "identity transformation returned an empty username, which is not allowed"

									.spec.identityProviders[0].transforms.examples[1] example failed:
									expected: no transformation errors
									actual:   transformations resulted in an unexpected error "identity transformation returned an empty username, which is not allowed"`,
							), frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has lots of errors including errors from multiple IDPs, which are all shown in the status conditions using IDP indices in the messages",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://not-unique.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "not unique",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     "this will not be found",
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Constants: []configv1alpha1.FederationDomainTransformsConstant{
										{Name: "foo", Type: "string", StringValue: "bar"},
										{Name: "foo", Type: "string", StringValue: "baz"},
									},
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `username + ":suffix"`},
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{ // this should fail
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "this is wrong string",
												Groups:   []string{"this is wrong string list"},
											},
										},
										{ // this should fail
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "this is also wrong string",
												Groups:   []string{"this is also wrong string list"},
											},
										},
									},
								},
							},
							{
								DisplayName: "not unique",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "this is wrong",
									Name:     "foo",
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Constants: []configv1alpha1.FederationDomainTransformsConstant{
										{Name: "foo", Type: "string", StringValue: "bar"},
										{Name: "foo", Type: "string", StringValue: "baz"},
									},
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `username + ":suffix"`},
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{ // this should pass
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "ryan:suffix",
												Groups:   []string{"a", "b"},
											},
										},
										{ // this should fail
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "this is still wrong string",
												Groups:   []string{"this is still wrong string list"},
											},
										},
									},
								},
							},
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String("this is wrong"),
									Kind:     "OIDCIdentityProvider",
									Name:     "foo",
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `username`},
										{Type: "username/v1", Expression: `this does not compile`},
										{Type: "username/v1", Expression: `username`},
										{Type: "username/v1", Expression: `this also does not compile`},
									},
								},
							},
						},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://not-unique.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `username`},
										{Type: "username/v1", Expression: `this still does not compile`},
										{Type: "username/v1", Expression: `username`},
										{Type: "username/v1", Expression: `this really does not compile`},
									},
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
					replaceConditions(
						allHappyConditionsSuccess("https://not-unique.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadConstNamesUniqueCondition(here.Doc(
								`the names specified by .spec.identityProviders[0].transforms.constants[].name contain duplicates: "foo"

									the names specified by .spec.identityProviders[1].transforms.constants[].name contain duplicates: "foo"`,
							), frozenMetav1Now, 123),
							sadAPIGroupSuffixCondition(`"this is wrong"`, frozenMetav1Now, 123),
							sadDisplayNamesUniqueCondition(`"not unique"`, frozenMetav1Now, 123),
							sadIdentityProvidersFoundConditionIdentityProvidersObjectRefsNotFound(
								`.spec.identityProviders[0] with displayName "not unique", .spec.identityProviders[1] with displayName "not unique", .spec.identityProviders[2] with displayName "name1"`,
								frozenMetav1Now, 123),
							sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
							sadKindCondition(`"this is wrong"`, frozenMetav1Now, 123),
							sadTransformationExpressionsCondition(here.Doc(
								`spec.identityProvider[2].transforms.expressions[1].expression was invalid:
									CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'does' expecting <EOF>
									 | this does not compile
									 | .....^

									spec.identityProvider[2].transforms.expressions[3].expression was invalid:
									CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'also' expecting <EOF>
									 | this also does not compile
									 | .....^`,
							), frozenMetav1Now, 123),
							sadTransformationExamplesCondition(here.Doc(
								`.spec.identityProviders[0].transforms.examples[0] example failed:
									expected: username "this is wrong string"
									actual:   username "ryan:suffix"

									.spec.identityProviders[0].transforms.examples[0] example failed:
									expected: groups ["this is wrong string list"]
									actual:   groups ["a", "b"]

									.spec.identityProviders[0].transforms.examples[1] example failed:
									expected: username "this is also wrong string"
									actual:   username "ryan:suffix"

									.spec.identityProviders[0].transforms.examples[1] example failed:
									expected: groups ["this is also wrong string list"]
									actual:   groups ["a", "b"]

									.spec.identityProviders[1].transforms.examples[1] example failed:
									expected: username "this is still wrong string"
									actual:   username "ryan:suffix"

									.spec.identityProviders[1].transforms.examples[1] example failed:
									expected: groups ["this is still wrong string list"]
									actual:   groups ["a", "b"]

									unable to check if the examples specified by .spec.identityProviders[2].transforms.examples[] had errors because an expression was invalid`,
							), frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
				expectedFederationDomainStatusUpdate(
					&configv1alpha1.FederationDomain{
						ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
					},
					configv1alpha1.FederationDomainPhaseError,
					replaceConditions(
						allHappyConditionsSuccess("https://not-unique.com", frozenMetav1Now, 123),
						[]configv1alpha1.Condition{
							sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
							sadTransformationExpressionsCondition(here.Doc(
								`spec.identityProvider[0].transforms.expressions[1].expression was invalid:
									CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'still' expecting <EOF>
									 | this still does not compile
									 | .....^

									spec.identityProvider[0].transforms.expressions[3].expression was invalid:
									CEL expression compile error: ERROR: <input>:1:6: Syntax error: mismatched input 'really' expecting <EOF>
									 | this really does not compile
									 | .....^`,
							), frozenMetav1Now, 123),
							sadTransformationExamplesCondition(
								"unable to check if the examples specified by .spec.identityProviders[0].transforms.examples[] had errors because an expression was invalid",
								frozenMetav1Now, 123),
							sadReadyCondition(frozenMetav1Now, 123),
						}),
				),
			},
		},
		{
			name: "the federation domain has valid IDPs and transformations and examples",
			inputObjects: []runtime.Object{
				oidcIdentityProvider,
				ldapIdentityProvider,
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer1.com",
						IdentityProviders: []configv1alpha1.FederationDomainIdentityProvider{
							{
								DisplayName: "name1",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "OIDCIdentityProvider",
									Name:     oidcIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "policy/v1", Expression: `username == "ryan" || username == "rejectMeWithDefaultMessage"`, Message: "only ryan allowed"},
										{Type: "policy/v1", Expression: `username != "rejectMeWithDefaultMessage"`}, // no message specified
										{Type: "username/v1", Expression: `"pre:" + username`},
										{Type: "groups/v1", Expression: `groups.map(g, "pre:" + g)`},
									},
									Constants: []configv1alpha1.FederationDomainTransformsConstant{
										{Name: "str", Type: "string", StringValue: "abc"},
										{Name: "strL", Type: "stringList", StringListValue: []string{"def"}},
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "pre:ryan",
												Groups:   []string{"pre:b", "pre:a"},
												Rejected: false,
											},
										},
										{
											Username: "other",
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												Message:  "only ryan allowed",
											},
										},
										{
											Username: "rejectMeWithDefaultMessage",
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												// Not specifying message is the same as expecting the default message.
											},
										},
										{
											Username: "rejectMeWithDefaultMessage",
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Rejected: true,
												Message:  "authentication was rejected by a configured policy", // this is the default message
											},
										},
									},
								},
							},
							{
								DisplayName: "name2",
								ObjectRef: corev1.TypedLocalObjectReference{
									APIGroup: pointer.String(apiGroupSupervisor),
									Kind:     "LDAPIdentityProvider",
									Name:     ldapIdentityProvider.Name,
								},
								Transforms: configv1alpha1.FederationDomainTransforms{
									Expressions: []configv1alpha1.FederationDomainTransformsExpression{
										{Type: "username/v1", Expression: `"pre:" + username`},
									},
									Examples: []configv1alpha1.FederationDomainTransformsExample{
										{
											Username: "ryan",
											Groups:   []string{"a", "b"},
											Expects: configv1alpha1.FederationDomainTransformsExampleExpects{
												Username: "pre:ryan",
												Groups:   []string{"b", "a"},
												Rejected: false,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantFDIssuers: []*federationdomainproviders.FederationDomainIssuer{
				federationDomainIssuerWithIDPs(t, "https://issuer1.com", []*federationdomainproviders.FederationDomainIdentityProvider{
					{
						DisplayName: "name1",
						UID:         oidcIdentityProvider.UID,
						Transforms: newTransformationPipeline(t, &celtransformer.TransformationConstants{
							StringConstants:     map[string]string{"str": "abc"},
							StringListConstants: map[string][]string{"strL": {"def"}},
						},
							&celtransformer.AllowAuthenticationPolicy{
								Expression:                    `username == "ryan" || username == "rejectMeWithDefaultMessage"`,
								RejectedAuthenticationMessage: "only ryan allowed",
							},
							&celtransformer.AllowAuthenticationPolicy{Expression: `username != "rejectMeWithDefaultMessage"`},
							&celtransformer.UsernameTransformation{Expression: `"pre:" + username`},
							&celtransformer.GroupsTransformation{Expression: `groups.map(g, "pre:" + g)`},
						),
					},
					{
						DisplayName: "name2",
						UID:         ldapIdentityProvider.UID,
						Transforms: newTransformationPipeline(t, &celtransformer.TransformationConstants{},
							&celtransformer.UsernameTransformation{Expression: `"pre:" + username`},
						),
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
				apiGroupSuffix,
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
				// This is ugly, but we cannot test equality on compiled identity transformations because cel.Program
				// cannot be compared for equality. This converts them to a type which can be tested for equality,
				// which should be good enough for the purposes of this test.
				require.ElementsMatch(t,
					convertToComparableType(tt.wantFDIssuers),
					convertToComparableType(federationDomainsSetter.FederationDomainsReceived))
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

type comparableFederationDomainIssuer struct {
	issuer                  string
	identityProviders       []*comparableFederationDomainIdentityProvider
	defaultIdentityProvider *comparableFederationDomainIdentityProvider
}

type comparableFederationDomainIdentityProvider struct {
	DisplayName      string
	UID              types.UID
	TransformsSource []interface{}
}

func makeFederationDomainIdentityProviderComparable(fdi *federationdomainproviders.FederationDomainIdentityProvider) *comparableFederationDomainIdentityProvider {
	if fdi == nil {
		return nil
	}
	return &comparableFederationDomainIdentityProvider{
		DisplayName:      fdi.DisplayName,
		UID:              fdi.UID,
		TransformsSource: fdi.Transforms.Source(),
	}
}

func convertToComparableType(fdis []*federationdomainproviders.FederationDomainIssuer) []*comparableFederationDomainIssuer {
	result := []*comparableFederationDomainIssuer{}
	for _, fdi := range fdis {
		comparableFDIs := make([]*comparableFederationDomainIdentityProvider, len(fdi.IdentityProviders()))
		for _, idp := range fdi.IdentityProviders() {
			comparableFDIs = append(comparableFDIs, makeFederationDomainIdentityProviderComparable(idp))
		}
		converted := &comparableFederationDomainIssuer{
			issuer:                  fdi.Issuer(),
			identityProviders:       comparableFDIs,
			defaultIdentityProvider: makeFederationDomainIdentityProviderComparable(fdi.DefaultIdentityProvider()),
		}
		result = append(result, converted)
	}
	return result
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

func newTransformationPipeline(
	t *testing.T,
	consts *celtransformer.TransformationConstants,
	transformations ...celtransformer.CELTransformation,
) *idtransform.TransformationPipeline {
	pipeline := idtransform.NewTransformationPipeline()

	compiler, err := celtransformer.NewCELTransformer(celTransformerMaxExpressionRuntime)
	require.NoError(t, err)

	if consts.StringConstants == nil {
		consts.StringConstants = map[string]string{}
	}
	if consts.StringListConstants == nil {
		consts.StringListConstants = map[string][]string{}
	}

	for _, transform := range transformations {
		compiledTransform, err := compiler.CompileTransformation(transform, consts)
		require.NoError(t, err)
		pipeline.AppendTransformation(compiledTransform)
	}

	return pipeline
}

func TestTransformationPipelinesCanBeTestedForEqualityUsingSourceToMakeTestingEasier(t *testing.T) {
	compiler, err := celtransformer.NewCELTransformer(5 * time.Second)
	require.NoError(t, err)

	transforms := []celtransformer.CELTransformation{
		&celtransformer.AllowAuthenticationPolicy{
			Expression:                    `username == "ryan" || username == "rejectMeWithDefaultMessage"`,
			RejectedAuthenticationMessage: "only ryan allowed",
		},
		&celtransformer.UsernameTransformation{Expression: `"pre:" + username`},
		&celtransformer.GroupsTransformation{Expression: `groups.map(g, "pre:" + g)`},
	}

	differentTransforms := []celtransformer.CELTransformation{
		&celtransformer.AllowAuthenticationPolicy{
			Expression:                    `username == "ryan" || username == "different"`,
			RejectedAuthenticationMessage: "different",
		},
		&celtransformer.UsernameTransformation{Expression: `"different:" + username`},
		&celtransformer.GroupsTransformation{Expression: `groups.map(g, "different:" + g)`},
	}

	consts := &celtransformer.TransformationConstants{
		StringConstants: map[string]string{
			"foo": "bar",
			"baz": "bat",
		},
		StringListConstants: map[string][]string{
			"foo": {"a", "b"},
			"bar": {"c", "d"},
		},
	}

	differentConsts := &celtransformer.TransformationConstants{
		StringConstants: map[string]string{
			"foo": "barDifferent",
			"baz": "bat",
		},
		StringListConstants: map[string][]string{
			"foo": {"aDifferent", "b"},
			"bar": {"c", "d"},
		},
	}

	pipeline := idtransform.NewTransformationPipeline()
	equalPipeline := idtransform.NewTransformationPipeline()
	differentPipeline1 := idtransform.NewTransformationPipeline()
	differentPipeline2 := idtransform.NewTransformationPipeline()
	expectedSourceList := []interface{}{}

	for i, transform := range transforms {
		// Compile and append to a pipeline.
		compiledTransform1, err := compiler.CompileTransformation(transform, consts)
		require.NoError(t, err)
		pipeline.AppendTransformation(compiledTransform1)

		// Recompile the same thing and append it to another pipeline.
		// This pipeline should end up being equal to the first one.
		compiledTransform2, err := compiler.CompileTransformation(transform, consts)
		require.NoError(t, err)
		equalPipeline.AppendTransformation(compiledTransform2)

		// Build up a test expectation value.
		expectedSourceList = append(expectedSourceList, &celtransformer.CELTransformationSource{Expr: transform, Consts: consts})

		// Compile a different expression using the same constants and append it to a different pipeline.
		// This should not be equal to the other pipelines.
		compiledDifferentExpressionSameConsts, err := compiler.CompileTransformation(differentTransforms[i], consts)
		require.NoError(t, err)
		differentPipeline1.AppendTransformation(compiledDifferentExpressionSameConsts)

		// Compile the same expression using the different constants and append it to a different pipeline.
		// This should not be equal to the other pipelines.
		compiledSameExpressionDifferentConsts, err := compiler.CompileTransformation(transform, differentConsts)
		require.NoError(t, err)
		differentPipeline2.AppendTransformation(compiledSameExpressionDifferentConsts)
	}

	require.Equal(t, expectedSourceList, pipeline.Source())
	require.Equal(t, expectedSourceList, equalPipeline.Source())

	// The source of compiled pipelines can be compared to each other in this way for testing purposes.
	require.Equal(t, pipeline.Source(), equalPipeline.Source())
	require.NotEqual(t, pipeline.Source(), differentPipeline1.Source())
	require.NotEqual(t, pipeline.Source(), differentPipeline2.Source())
}
