// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestJWKSObserverControllerInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                                *require.Assertions
			observableWithInformerOption     *testutil.ObservableWithInformerOption
			secretsInformerFilter            controllerlib.Filter
			oidcProviderConfigInformerFilter controllerlib.Filter
		)

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			oidcProviderConfigInformer := pinnipedinformers.NewSharedInformerFactory(nil, 0).Config().V1alpha1().OIDCProviderConfigs()
			_ = NewJWKSObserverController(
				nil,
				secretsInformer,
				oidcProviderConfigInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
			oidcProviderConfigInformerFilter = observableWithInformerOption.GetFilterForInformer(oidcProviderConfigInformer)
		})

		when("watching Secret objects", func() {
			var (
				subject             controllerlib.Filter
				secret, otherSecret *corev1.Secret
			)

			it.Before(func() {
				subject = secretsInformerFilter
				secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}}
				otherSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}}
			})

			when("any Secret changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(secret))
					r.True(subject.Update(secret, otherSecret))
					r.True(subject.Update(otherSecret, secret))
					r.True(subject.Delete(secret))
				})
			})
		})

		when("watching OIDCProviderConfig objects", func() {
			var (
				subject                 controllerlib.Filter
				provider, otherProvider *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				subject = oidcProviderConfigInformerFilter
				provider = &v1alpha1.OIDCProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}}
				otherProvider = &v1alpha1.OIDCProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}}
			})

			when("any OIDCProviderConfig changes", func() {
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
	setIssuerToJWKSMapWasCalled bool
	issuerToJWKSMapReceived     map[string]*jose.JSONWebKeySet
}

func (f *fakeIssuerToJWKSMapSetter) SetIssuerToJWKSMap(issuerToJWKSMap map[string]*jose.JSONWebKeySet) {
	f.setIssuerToJWKSMapWasCalled = true
	f.issuerToJWKSMapReceived = issuerToJWKSMap
}

func TestJWKSObserverControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var (
			r                      *require.Assertions
			subject                controllerlib.Controller
			pinnipedInformerClient *pinnipedfake.Clientset
			kubeInformerClient     *kubernetesfake.Clientset
			pinnipedInformers      pinnipedinformers.SharedInformerFactory
			kubeInformers          kubeinformers.SharedInformerFactory
			timeoutContext         context.Context
			timeoutContextCancel   context.CancelFunc
			syncContext            *controllerlib.Context
			issuerToJWKSSetter     *fakeIssuerToJWKSMapSetter
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewJWKSObserverController(
				issuerToJWKSSetter,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCProviderConfigs(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      "any-name",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			pinnipedInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			pinnipedInformerClient = pinnipedfake.NewSimpleClientset()
			pinnipedInformers = pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)
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
			timeoutContextCancel()
		})

		when("there are no OIDCProviderConfigs and no JWKS Secrets yet", func() {
			it("sets the issuerToJWKSSetter's map to be empty", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				r.True(issuerToJWKSSetter.setIssuerToJWKSMapWasCalled)
				r.Empty(issuerToJWKSSetter.issuerToJWKSMapReceived)
			})
		})

		when("there are OIDCProviderConfigs where some have corresponding JWKS Secrets and some don't", func() {
			var (
				expectedJWK1, expectedJWK2 string
			)

			it.Before(func() {
				oidcProviderConfigWithoutSecret1 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-oidcproviderconfig1",
						Namespace: installedInNamespace,
					},
					Spec:   v1alpha1.OIDCProviderConfigSpec{Issuer: "https://no-secret-issuer1.com"},
					Status: v1alpha1.OIDCProviderConfigStatus{}, // no JWKSSecret field
				}
				oidcProviderConfigWithoutSecret2 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-oidcproviderconfig2",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.OIDCProviderConfigSpec{Issuer: "https://no-secret-issuer2.com"},
					// no Status field
				}
				oidcProviderConfigWithBadSecret := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-secret-oidcproviderconfig",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.OIDCProviderConfigSpec{Issuer: "https://bad-secret-issuer.com"},
					Status: v1alpha1.OIDCProviderConfigStatus{
						JWKSSecret: corev1.LocalObjectReference{Name: "bad-jwks-secret-name"},
					},
				}
				oidcProviderConfigWithGoodSecret1 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-oidcproviderconfig1",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer-with-good-secret1.com"},
					Status: v1alpha1.OIDCProviderConfigStatus{
						JWKSSecret: corev1.LocalObjectReference{Name: "good-jwks-secret-name1"},
					},
				}
				oidcProviderConfigWithGoodSecret2 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-oidcproviderconfig2",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer-with-good-secret2.com"},
					Status: v1alpha1.OIDCProviderConfigStatus{
						JWKSSecret: corev1.LocalObjectReference{Name: "good-jwks-secret-name2"},
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
				badJWKSSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-jwks-secret-name",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{"junk": nil},
				}
				r.NoError(pinnipedInformerClient.Tracker().Add(oidcProviderConfigWithoutSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(oidcProviderConfigWithoutSecret2))
				r.NoError(pinnipedInformerClient.Tracker().Add(oidcProviderConfigWithBadSecret))
				r.NoError(pinnipedInformerClient.Tracker().Add(oidcProviderConfigWithGoodSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(oidcProviderConfigWithGoodSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(goodJWKSSecret1))
				r.NoError(kubeInformerClient.Tracker().Add(goodJWKSSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(badJWKSSecret))
			})

			requireJWKJSON := func(expectedJWKJSON string, actualJWKS *jose.JSONWebKeySet) {
				r.NotNil(actualJWKS)
				r.Len(actualJWKS.Keys, 1)
				actualJWK := actualJWKS.Keys[0]
				actualJWKJSON, err := json.Marshal(actualJWK)
				r.NoError(err)
				r.JSONEq(expectedJWKJSON, string(actualJWKJSON))
			}

			it("updates the issuerToJWKSSetter's map to include only the issuers that had valid JWKS", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.True(issuerToJWKSSetter.setIssuerToJWKSMapWasCalled)
				r.Len(issuerToJWKSSetter.issuerToJWKSMapReceived, 2)

				// the actual JWK should match the one from the test fixture that was put into the secret
				requireJWKJSON(expectedJWK1, issuerToJWKSSetter.issuerToJWKSMapReceived["https://issuer-with-good-secret1.com"])
				requireJWKJSON(expectedJWK2, issuerToJWKSSetter.issuerToJWKSMapReceived["https://issuer-with-good-secret2.com"])
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
