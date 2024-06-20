// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	supervisorinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestJWKSObserverControllerInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                              *require.Assertions
			observableWithInformerOption   *testutil.ObservableWithInformerOption
			secretsInformerFilter          controllerlib.Filter
			federationDomainInformerFilter controllerlib.Filter
		)

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			secretsInformer := k8sinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			federationDomainInformer := supervisorinformers.NewSharedInformerFactory(nil, 0).Config().V1alpha1().FederationDomains()
			_ = NewJWKSObserverController(
				nil,
				secretsInformer,
				federationDomainInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
			federationDomainInformerFilter = observableWithInformerOption.GetFilterForInformer(federationDomainInformer)
		})

		when("watching Secret objects", func() {
			var (
				subject                 controllerlib.Filter
				secret, otherTypeSecret *corev1.Secret
			)

			it.Before(func() {
				subject = secretsInformerFilter
				secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}, Type: "secrets.pinniped.dev/federation-domain-jwks"}
				otherTypeSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}, Type: "other"}
			})

			when("any Secret of the JWKS type changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(secret))
					r.True(subject.Update(secret, otherTypeSecret))
					r.True(subject.Update(otherTypeSecret, secret))
					r.True(subject.Delete(secret))
				})
			})

			when("any Secret of some other type changes", func() {
				it("returns false to skip the sync method", func() {
					r.False(subject.Add(otherTypeSecret))
					r.False(subject.Update(otherTypeSecret, otherTypeSecret))
					r.False(subject.Update(otherTypeSecret, otherTypeSecret))
					r.False(subject.Delete(otherTypeSecret))
				})
			})
		})

		when("watching FederationDomain objects", func() {
			var (
				subject                 controllerlib.Filter
				provider, otherProvider *supervisorconfigv1alpha1.FederationDomain
			)

			it.Before(func() {
				subject = federationDomainInformerFilter
				provider = &supervisorconfigv1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}}
				otherProvider = &supervisorconfigv1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}}
			})

			when("any FederationDomain changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(provider))
					r.True(subject.Update(provider, otherProvider))
					r.True(subject.Update(otherProvider, provider))
					r.True(subject.Delete(provider))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

type fakeIssuerToJWKSMapSetter struct {
	setIssuerToJWKSMapWasCalled  bool
	issuerToJWKSMapReceived      map[string]*jose.JSONWebKeySet
	issuerToActiveJWKMapReceived map[string]*jose.JSONWebKey
}

func (f *fakeIssuerToJWKSMapSetter) SetIssuerToJWKSMap(
	issuerToJWKSMap map[string]*jose.JSONWebKeySet,
	issuerToActiveJWKMap map[string]*jose.JSONWebKey,
) {
	f.setIssuerToJWKSMapWasCalled = true
	f.issuerToJWKSMapReceived = issuerToJWKSMap
	f.issuerToActiveJWKMapReceived = issuerToActiveJWKMap
}

func TestJWKSObserverControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var (
			r                       *require.Assertions
			subject                 controllerlib.Controller
			pinnipedInformerClient  *supervisorfake.Clientset
			kubeInformerClient      *kubernetesfake.Clientset
			pinnipedInformers       supervisorinformers.SharedInformerFactory
			kubeInformers           k8sinformers.SharedInformerFactory
			cancelContext           context.Context
			cancelContextCancelFunc context.CancelFunc
			syncContext             *controllerlib.Context
			issuerToJWKSSetter      *fakeIssuerToJWKSMapSetter
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewJWKSObserverController(
				issuerToJWKSSetter,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: cancelContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      "any-name",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(cancelContext.Done())
			pinnipedInformers.Start(cancelContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			cancelContext, cancelContextCancelFunc = context.WithCancel(context.Background())

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = k8sinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			pinnipedInformerClient = supervisorfake.NewSimpleClientset()
			pinnipedInformers = supervisorinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)
			issuerToJWKSSetter = &fakeIssuerToJWKSMapSetter{}

			unrelatedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some other unrelated secret",
					Namespace: installedInNamespace,
				},
			}
			r.NoError(kubeInformerClient.Tracker().Add(unrelatedSecret))
		})

		it.After(func() {
			cancelContextCancelFunc()
		})

		when("there are no FederationDomains and no JWKS Secrets yet", func() {
			it("sets the issuerToJWKSSetter's map to be empty", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				r.True(issuerToJWKSSetter.setIssuerToJWKSMapWasCalled)
				r.Empty(issuerToJWKSSetter.issuerToJWKSMapReceived)
				r.Empty(issuerToJWKSSetter.issuerToActiveJWKMapReceived)
			})
		})

		when("there are FederationDomains where some have corresponding JWKS Secrets and some don't", func() {
			var (
				expectedJWK1, expectedJWK2 string
			)

			it.Before(func() {
				federationDomainWithoutSecret1 := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-federationdomain1",
						Namespace: installedInNamespace,
					},
					Spec:   supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://no-secret-issuer1.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{}, // no Secrets.JWKS field
				}
				federationDomainWithoutSecret2 := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-federationdomain2",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://no-secret-issuer2.com"},
					// no Status field
				}
				federationDomainWithBadSecret := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-secret-federationdomain",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://bad-secret-issuer.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{
						Secrets: supervisorconfigv1alpha1.FederationDomainSecrets{
							JWKS: corev1.LocalObjectReference{Name: "bad-secret-name"},
						},
					},
				}
				federationDomainWithBadJWKSSecret := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-jwks-secret-federationdomain",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://bad-jwks-secret-issuer.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{
						Secrets: supervisorconfigv1alpha1.FederationDomainSecrets{
							JWKS: corev1.LocalObjectReference{Name: "bad-jwks-secret-name"},
						},
					},
				}
				federationDomainWithBadActiveJWKSecret := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-active-jwk-secret-federationdomain",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://bad-active-jwk-secret-issuer.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{
						Secrets: supervisorconfigv1alpha1.FederationDomainSecrets{
							JWKS: corev1.LocalObjectReference{Name: "bad-active-jwk-secret-name"},
						},
					},
				}
				federationDomainWithGoodSecret1 := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-federationdomain1",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://issuer-with-good-secret1.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{
						Secrets: supervisorconfigv1alpha1.FederationDomainSecrets{
							JWKS: corev1.LocalObjectReference{Name: "good-jwks-secret-name1"},
						},
					},
				}
				federationDomainWithGoodSecret2 := &supervisorconfigv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-federationdomain2",
						Namespace: installedInNamespace,
					},
					Spec: supervisorconfigv1alpha1.FederationDomainSpec{Issuer: "https://issuer-with-good-secret2.com"},
					Status: supervisorconfigv1alpha1.FederationDomainStatus{
						Secrets: supervisorconfigv1alpha1.FederationDomainSecrets{
							JWKS: corev1.LocalObjectReference{Name: "good-jwks-secret-name2"},
						},
					},
				}
				expectedJWK1 = string(readJWKJSON(t, "testdata/public-jwk.json"))
				r.NotEmpty(expectedJWK1)
				expectedJWK2 = string(readJWKJSON(t, "testdata/public-jwk2.json"))
				r.NotEmpty(expectedJWK2)
				goodJWKSSecret1 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-jwks-secret-name1",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						"activeJWK": []byte(expectedJWK1),
						"jwks":      []byte(`{"keys": [` + expectedJWK1 + `]}`),
					},
				}
				goodJWKSSecret2 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-jwks-secret-name2",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						"activeJWK": []byte(expectedJWK2),
						"jwks":      []byte(`{"keys": [` + expectedJWK2 + `]}`),
					},
				}
				badSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-secret-name",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{"junk": nil},
				}
				badJWKSSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-jwks-secret-name",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						"activeJWK": []byte(expectedJWK2),
						"jwks":      []byte("bad"),
					},
				}
				badActiveJWKSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-active-jwk-secret-name",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						"activeJWK": []byte("bad"),
						"jwks":      []byte(`{"keys": [` + expectedJWK2 + `]}`),
					},
				}
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithoutSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithoutSecret2))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithBadSecret))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithBadJWKSSecret))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithBadActiveJWKSecret))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithGoodSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithGoodSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(goodJWKSSecret1))
				r.NoError(kubeInformerClient.Tracker().Add(goodJWKSSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(badSecret))
				r.NoError(kubeInformerClient.Tracker().Add(badJWKSSecret))
				r.NoError(kubeInformerClient.Tracker().Add(badActiveJWKSecret))
			})

			requireJWKSJSON := func(expectedJWKJSON string, actualJWKS *jose.JSONWebKeySet) {
				r.NotNil(actualJWKS)
				r.Len(actualJWKS.Keys, 1)
				actualJWK := actualJWKS.Keys[0]
				actualJWKJSON, err := json.Marshal(actualJWK)
				r.NoError(err)
				r.JSONEq(expectedJWKJSON, string(actualJWKJSON))
			}

			requireJWKJSON := func(expectedJWKJSON string, actualJWK *jose.JSONWebKey) {
				r.NotNil(actualJWK)
				actualJWKJSON, err := json.Marshal(actualJWK)
				r.NoError(err)
				r.JSONEq(expectedJWKJSON, string(actualJWKJSON))
			}

			it("updates the issuerToJWKSSetter's map to include only the issuers that had valid JWKS", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.True(issuerToJWKSSetter.setIssuerToJWKSMapWasCalled)
				r.Len(issuerToJWKSSetter.issuerToJWKSMapReceived, 2)
				r.Len(issuerToJWKSSetter.issuerToActiveJWKMapReceived, 2)

				// the actual JWK should match the one from the test fixture that was put into the secret
				requireJWKSJSON(expectedJWK1, issuerToJWKSSetter.issuerToJWKSMapReceived["https://issuer-with-good-secret1.com"])
				requireJWKJSON(expectedJWK1, issuerToJWKSSetter.issuerToActiveJWKMapReceived["https://issuer-with-good-secret1.com"])
				requireJWKSJSON(expectedJWK2, issuerToJWKSSetter.issuerToJWKSMapReceived["https://issuer-with-good-secret2.com"])
				requireJWKJSON(expectedJWK2, issuerToJWKSSetter.issuerToActiveJWKMapReceived["https://issuer-with-good-secret2.com"])
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
